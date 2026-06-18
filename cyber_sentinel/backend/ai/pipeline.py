"""
AI Pipeline Orchestrator v2.0

Full processing flow:
  1. Fetch raw intel record
  2. Classify (two-stage: keyword fast → NLI slow)
  3. Extract ScamDNA v2.0 (Aadhaar, PAN, IFSC, shortened URLs, etc.)
  4. Compute multi-factor risk score v2.0
  5. Campaign clustering (hybrid: semantic + type agreement)
  6. Persist ScamArtifact with all new fields
  7. Write immutable ThreatHistory entry
  8. Update SuspectPhoneNumber registry (cross-campaign tracking)
  9. Update SuspectDomain registry (blocklist with provenance)
  10. Update IndiaGeoHeatmap (for O(1) choropleth rendering)
"""

from sqlalchemy.orm import Session
from sqlalchemy import func
from backend import models
from .classifier import ScamClassifier
from .dna_extractor import DNAExtractor
from .clusterer import CampaignClusterer
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)


def _utcnow():
    return datetime.now(timezone.utc)


class AnalyticsPipeline:
    """
    Orchestrates the full intelligence processing pipeline:
      1. Classify → 2. Extract DNA → 3. Score → 4. Cluster → 5. Persist → 6. Update Registries
    """

    def __init__(self):
        self.classifier = ScamClassifier()
        self.extractor = DNAExtractor()
        self.clusterer = CampaignClusterer()
        logger.info("[Pipeline] AnalyticsPipeline v2.0 initialized.")

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

        # 2. Guard: skip if already processed
        already_processed = (
            db.query(models.ScamArtifact)
            .filter(models.ScamArtifact.raw_intel_id == raw_intel_id)
            .first()
        )
        if already_processed:
            logger.debug("[Pipeline] RawIntel id=%s already processed. Skipping.", raw_intel_id)
            return already_processed

        # 3. Classify text (two-stage)
        scam_type, confidence = self.classifier.classify_text(raw_record.raw_text)

        # 4. Extract ScamDNA v2.0
        dna = self.extractor.extract_dna(raw_record.raw_text)

        # 5. Compute multi-factor risk score v2.0
        risk = self.extractor.compute_risk(
            scam_type=scam_type,
            url_count=len(dna["urls"]),
            kw_count=len(dna["keywords"]),
            phone_count=len(dna["phone_numbers"]),
            psych_count=len(dna["psychological_triggers"]),
            confidence=confidence,
            email_count=len(dna.get("emails", [])),
            apk_count=len(dna.get("apks", [])),
            wallet_count=len(dna.get("wallets", [])),
            bank_count=len(dna.get("banks", [])),
            shortened_url_count=len(dna.get("shortened_urls", [])),
        )

        # 6. Campaign clustering (only for suspicious content)
        is_suspicious = scam_type != "Safe / Non-Scam"
        assigned_campaign = None
        similarity_score = 0.0

        if is_suspicious:
            history = (
                db.query(models.RawIntel.raw_text, models.ScamArtifact.campaign_id, models.ScamArtifact.scam_type)
                .join(models.ScamArtifact, models.RawIntel.id == models.ScamArtifact.raw_intel_id)
                .filter(models.ScamArtifact.campaign_id.isnot(None))
                .limit(300)   # Increased cap for better clustering accuracy
                .all()
            )
            formatted_history = [
                {"text": h.raw_text, "campaign_id": h.campaign_id, "scam_type": h.scam_type}
                for h in history
            ]
            assigned_campaign, similarity_score = self.clusterer.resolve_campaign(
                raw_record.raw_text,
                formatted_history,
                new_scam_type=scam_type,
            )

        # 7. Persist ScamArtifact with all new fields
        primary_state = dna.get("primary_state")
        primary_district = dna.get("primary_district")

        artifact = models.ScamArtifact(
            raw_intel_id=raw_record.id,
            campaign_id=assigned_campaign,
            scam_type=scam_type,
            confidence_score=round(confidence, 4),
            keywords=",".join(dna["keywords"]),
            extracted_urls=",".join(dna["urls"]),
            shortened_urls=",".join(dna.get("shortened_urls", [])),
            platform=raw_record.source,
            geo_references=",".join(dna["geo_references"]),
            state=primary_state,
            district=primary_district,
            extracted_emails=",".join(dna.get("emails", [])),
            extracted_apks=",".join(dna.get("apks", [])),
            extracted_handles=",".join(dna.get("handles", [])),
            wallet_addresses=",".join(dna.get("wallets", [])),
            bank_references=",".join(dna.get("banks", [])),
            wa_links=",".join(dna.get("wa_links", [])),
            tg_links=",".join(dna.get("tg_links", [])),
            aadhaar_refs=",".join(dna.get("aadhaar_refs", [])),
            pan_refs=",".join(dna.get("pan_refs", [])),
            ifsc_codes=",".join(dna.get("ifsc_codes", [])),
            risk_score=risk if is_suspicious else 0.0,
            status="New" if is_suspicious else "Clean",
        )
        db.add(artifact)
        db.commit()
        db.refresh(artifact)

        # 8. Write immutable ThreatHistory audit log
        if is_suspicious:
            verdict = _compute_verdict(risk)
            threat_log = models.ThreatHistory(
                scam_artifact_id=artifact.id,
                platform=raw_record.source,
                scam_type=scam_type,
                risk_score=risk,
                raw_text=raw_record.raw_text,
                verdict=verdict,
                state=primary_state,
                district=primary_district,
            )
            db.add(threat_log)
            db.commit()

            # 9. Update SuspectPhoneNumber registry
            for phone in dna.get("phone_numbers", []):
                _upsert_suspect_phone(
                    db, phone, scam_type, raw_record.source,
                    assigned_campaign, primary_state
                )

            # 10. Update SuspectDomain registry
            for url in dna.get("urls", []):
                _upsert_suspect_domain(
                    db, url, scam_type, risk, raw_record.source,
                    assigned_campaign, url in dna.get("shortened_urls", [])
                )

            # 11. Update IndiaGeoHeatmap (if geo detected)
            if primary_state:
                _upsert_geo_heatmap(db, primary_state, scam_type, risk)

            recommended_action = _compute_recommended_action(scam_type, risk)
            entities_found = [
                f for f in [
                    f"Phones: {','.join(dna['phone_numbers'])}" if dna["phone_numbers"] else "",
                    f"URLs: {','.join(dna['urls'])}" if dna["urls"] else "",
                    f"Shortened URLs: {','.join(dna['shortened_urls'])}" if dna.get("shortened_urls") else "",
                    f"Emails: {','.join(dna.get('emails', []))}" if dna.get("emails") else "",
                    f"APKs: {','.join(dna.get('apks', []))}" if dna.get("apks") else "",
                    f"WhatsApp: {','.join(dna.get('wa_links', []))}" if dna.get("wa_links") else "",
                    f"Telegram: {','.join(dna.get('tg_links', []))}" if dna.get("tg_links") else "",
                    f"Aadhaar Refs: {len(dna.get('aadhaar_refs', []))} detected" if dna.get("aadhaar_refs") else "",
                    f"Banks: {','.join(dna.get('banks', []))}" if dna.get("banks") else "",
                ] if f
            ]

            log_output = f"""
Threat Type: {scam_type}
Confidence: {confidence:.2f}
Location: {primary_state or 'Unknown'} / {primary_district or 'Unknown'}
Geo Refs: {','.join(dna['geo_references']) if dna['geo_references'] else 'None'}
Entities Found: {' | '.join(entities_found) if entities_found else 'None'}
Associated Campaign: {assigned_campaign if assigned_campaign else 'Unclustered'}
Evidence Sources: {raw_record.source}
Risk Level: {verdict} ({risk:.1f}/100)
Recommended Action: {recommended_action}
"""
            logger.info("\nOUTPUT FORMAT FOR EVERY DETECTED THREAT:\n%s", log_output.strip())

        return artifact


# ─── Registry Upsert Helpers ──────────────────────────────────────────────────

def _upsert_suspect_phone(
    db: Session,
    phone: str,
    scam_type: str,
    platform: str,
    campaign_id: str | None,
    state: str | None,
):
    """Insert or update the SuspectPhoneNumber registry."""
    try:
        existing = db.query(models.SuspectPhoneNumber).filter(
            models.SuspectPhoneNumber.phone_number == phone
        ).first()

        if existing:
            existing.occurrence_count += 1
            existing.last_seen = _utcnow()
            # Append new scam type if not already present
            types = set((existing.scam_types or "").split(","))
            types.add(scam_type)
            existing.scam_types = ",".join(filter(None, types))
            # Append campaign ID
            camps = set((existing.campaign_ids or "").split(","))
            if campaign_id:
                camps.add(campaign_id)
            existing.campaign_ids = ",".join(filter(None, camps))
        else:
            db.add(models.SuspectPhoneNumber(
                phone_number=phone,
                occurrence_count=1,
                scam_types=scam_type,
                platforms=platform,
                campaign_ids=campaign_id or "",
                state=state,
            ))
        db.commit()
    except Exception as exc:
        logger.error("[Pipeline] SuspectPhone upsert error for %s: %s", phone, exc)
        db.rollback()


def _upsert_suspect_domain(
    db: Session,
    url: str,
    scam_type: str,
    risk_score: float,
    platform: str,
    campaign_id: str | None,
    is_shortened: bool,
):
    """Insert or update the SuspectDomain registry."""
    try:
        from urllib.parse import urlparse
        domain = urlparse(url).netloc.lower().lstrip("www.") or url[:100]

        existing = db.query(models.SuspectDomain).filter(
            models.SuspectDomain.domain == domain
        ).first()

        if existing:
            existing.occurrence_count += 1
            existing.last_seen = _utcnow()
            existing.max_risk_score = max(existing.max_risk_score, risk_score)
            types = set((existing.scam_types or "").split(","))
            types.add(scam_type)
            existing.scam_types = ",".join(filter(None, types))
        else:
            db.add(models.SuspectDomain(
                domain=domain,
                full_url=url[:512],
                occurrence_count=1,
                max_risk_score=risk_score,
                scam_types=scam_type,
                platforms=platform,
                campaign_ids=campaign_id or "",
                is_shortened=is_shortened,
            ))
        db.commit()
    except Exception as exc:
        logger.error("[Pipeline] SuspectDomain upsert error for %s: %s", url, exc)
        db.rollback()


def _upsert_geo_heatmap(db: Session, state: str, scam_type: str, risk_score: float):
    """Update IndiaGeoHeatmap counts for the detected state."""
    try:
        existing = db.query(models.IndiaGeoHeatmap).filter(
            models.IndiaGeoHeatmap.state == state
        ).first()

        if existing:
            existing.threat_count += 1
            if risk_score >= 75.0:
                existing.critical_count += 1
            elif risk_score >= 50.0:
                existing.high_count += 1
            existing.last_updated = _utcnow()
            # Keep track of most common scam type (simple approach: store latest)
            existing.top_scam_type = scam_type
        else:
            db.add(models.IndiaGeoHeatmap(
                state=state,
                threat_count=1,
                critical_count=1 if risk_score >= 75.0 else 0,
                high_count=1 if (50.0 <= risk_score < 75.0) else 0,
                top_scam_type=scam_type,
            ))
        db.commit()
    except Exception as exc:
        logger.error("[Pipeline] GeoHeatmap upsert error for %s: %s", state, exc)
        db.rollback()


# ─── Verdict & Action Helpers ─────────────────────────────────────────────────

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
    """Generate actionable recommendation based on scam type and risk level."""
    if risk_score >= 80.0:
        return (
            f"IMMEDIATE ACTION: Block all associated UPI IDs, domains, and phone numbers. "
            f"Issue public advisory for {scam_type}. Alert Nodal Officer and I4C. "
            f"File complaint on cybercrime.gov.in."
        )
    elif risk_score >= 60.0:
        return (
            f"Block associated UPI/domain infrastructure. Monitor {scam_type} campaign spread. "
            f"Notify relevant state cyber cell."
        )
    elif risk_score >= 40.0:
        return "Investigate extracted entities. Add phone/domain to watch-list. Cross-reference with NCRP."
    else:
        return "Log for intelligence gathering. Flag for follow-up if occurrence count increases."