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

            logger.info(
                "[Pipeline] Processed id=%s → %s | risk=%.1f | campaign=%s | verdict=%s",
                raw_intel_id, scam_type, risk, assigned_campaign, verdict,
            )

        return artifact


def _compute_verdict(risk_score: float) -> str:
    """Map numeric risk score to human-readable verdict string."""
    if risk_score >= 75.0:
        return "Highly Critical"
    elif risk_score >= 50.0:
        return "Suspicious (High Risk)"
    elif risk_score >= 25.0:
        return "Suspicious (Medium Risk)"
    else:
        return "Suspicious (Low Risk)"