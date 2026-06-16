from sqlalchemy.orm import Session
from app import models
from .classifier import ScamClassifier
from .dna_extractor import DNAExtractor
from .clusterer import CampaignClusterer
import logging

logger = logging.getLogger(__name__)


class AnalyticsPipeline:
    """
    Orchestrates the full intelligence processing pipeline:
      1. Classify → 2. Extract DNA → 3. Cluster → 4. Score → 5. Persist
    """

    def __init__(self):
        self.classifier = ScamClassifier()
        self.extractor = DNAExtractor()
        self.clusterer = CampaignClusterer()
        logger.info("[Pipeline] AnalyticsPipeline initialized.")

    def run_pipeline(self, raw_intel_id: int, db: Session) -> models.ScamArtifact | None:
        """
        Execute the full AI processing pipeline on a single raw intel record.

        Returns the created ScamArtifact, or None if the record was not found.
        """
        # 1. Fetch raw record
        raw_record = (
            db.query(models.RawIntel)
            .filter(models.RawIntel.id == raw_intel_id)
            .first()
        )
        if not raw_record:
            logger.warning("[Pipeline] RawIntel id=%s not found. Skipping.", raw_intel_id)
            return None

        # 2. Guard: skip if already processed (prevents duplicate artifacts)
        already_processed = (
            db.query(models.ScamArtifact)
            .filter(models.ScamArtifact.raw_intel_id == raw_intel_id)
            .first()
        )
        if already_processed:
            logger.debug("[Pipeline] RawIntel id=%s already processed. Skipping.", raw_intel_id)
            return already_processed

        # 3. Classify text
        scam_type, confidence = self.classifier.classify_text(raw_record.raw_text)

        # 4. Extract ScamDNA
        dna = self.extractor.extract_dna(raw_record.raw_text)

        # 5. Compute multi-factor risk score
        risk = self.extractor.compute_risk(
            scam_type=scam_type,
            url_count=len(dna["urls"]),
            kw_count=len(dna["keywords"]),
            phone_count=len(dna["phone_numbers"]),
            psych_count=len(dna["psychological_triggers"]),
            confidence=confidence,
        )

        # 6. Campaign clustering (only for suspicious content)
        is_suspicious = scam_type != "Safe / Non-Scam"
        assigned_campaign = None
        similarity_score = 0.0

        if is_suspicious:
            history = (
                db.query(models.RawIntel.raw_text, models.ScamArtifact.campaign_id)
                .join(models.ScamArtifact, models.RawIntel.id == models.ScamArtifact.raw_intel_id)
                .filter(models.ScamArtifact.campaign_id.isnot(None))
                .limit(200)   # Cap to avoid memory issues
                .all()
            )
            formatted_history = [
                {"text": h.raw_text, "campaign_id": h.campaign_id} for h in history
            ]
            assigned_campaign, similarity_score = self.clusterer.resolve_campaign(
                raw_record.raw_text, formatted_history
            )

        # 7. Persist ScamArtifact
        artifact = models.ScamArtifact(
            raw_intel_id=raw_record.id,
            campaign_id=assigned_campaign,
            scam_type=scam_type,
            confidence_score=round(confidence, 4),
            keywords=",".join(dna["keywords"]),
            extracted_urls=",".join(dna["urls"]),
            platform=raw_record.source,
            geo_references=",".join(dna["geo_references"]),
            extracted_emails=",".join(dna.get("emails", [])),
            extracted_apks=",".join(dna.get("apks", [])),
            extracted_handles=",".join(dna.get("handles", [])),
            wallet_addresses=",".join(dna.get("wallets", [])),
            bank_references=",".join(dna.get("banks", [])),
            risk_score=risk if is_suspicious else 0.0,
            status="New" if is_suspicious else "Clean",
        )
        db.add(artifact)
        db.commit()
        db.refresh(artifact)

        # 8. Write to immutable ThreatHistory audit log (suspicious only)
        if is_suspicious:
            verdict = _compute_verdict(risk)
            threat_log = models.ThreatHistory(
                scam_artifact_id=artifact.id,
                platform=raw_record.source,
                scam_type=scam_type,
                risk_score=risk,
                raw_text=raw_record.raw_text,
                verdict=verdict,
            )
            db.add(threat_log)
            db.commit()

            recommended_action = _compute_recommended_action(scam_type, risk)
            entities_found = [
                f for f in [
                    f"Phones: {','.join(dna['phone_numbers'])}" if dna["phone_numbers"] else "",
                    f"URLs: {','.join(dna['urls'])}" if dna["urls"] else "",
                    f"UPIs/Payments: {','.join(dna['payment_indicators'])}" if dna["payment_indicators"] else "",
                    f"Emails: {','.join(dna.get('emails', []))}" if dna.get("emails") else "",
                    f"APKs: {','.join(dna.get('apks', []))}" if dna.get("apks") else "",
                    f"Handles: {','.join(dna.get('handles', []))}" if dna.get("handles") else "",
                    f"Wallets: {','.join(dna.get('wallets', []))}" if dna.get("wallets") else "",
                    f"Banks: {','.join(dna.get('banks', []))}" if dna.get("banks") else "",
                ] if f
            ]

            log_output = f"""
Threat Type: {scam_type}
Confidence: {confidence:.2f}
Location: {",".join(dna["geo_references"]) if dna["geo_references"] else "Unknown"}
Entities Found: {" | ".join(entities_found) if entities_found else "None"}
Associated Campaign: {assigned_campaign if assigned_campaign else "Unclustered"}
Evidence Sources: {raw_record.source}
Risk Level: {verdict}
Recommended Action: {recommended_action}
"""
            logger.info("\nOUTPUT FORMAT FOR EVERY DETECTED THREAT:\n%s", log_output.strip())

        return artifact


def _compute_verdict(risk_score: float) -> str:
    """Map numeric risk score to human-readable verdict string."""
    if risk_score >= 80.0:
        return "Critical"
    elif risk_score >= 60.0:
        return "High"
    elif risk_score >= 40.0:
        return "Medium"
    else:
        return "Low"

def _compute_recommended_action(scam_type: str, risk_score: float) -> str:
    if risk_score >= 80.0:
        return f"Immediate takedown of {scam_type} infrastructure, issue public advisory, alert Nodal Officer."
    elif risk_score >= 60.0:
        return f"Block associated UPI/domains, monitor {scam_type} campaign spread."
    elif risk_score >= 40.0:
        return "Investigate entities, add to watch-list."
    else:
        return "Log for intelligence gathering."