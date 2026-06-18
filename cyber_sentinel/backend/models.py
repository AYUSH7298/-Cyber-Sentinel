from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text, Index, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from .database import Base


def _utcnow():
    """Timezone-aware UTC timestamp helper (replaces deprecated datetime.utcnow)."""
    return datetime.now(timezone.utc)


class RawIntel(Base):
    """Raw intelligence record as ingested from collectors before AI processing."""
    __tablename__ = "raw_intel"

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String(64), nullable=False, index=True)   # 'telegram', 'rss', 'reddit', 'manual'
    raw_text = Column(Text, nullable=False)
    content_hash = Column(String(64), unique=True, index=True, nullable=True)  # SHA-256 for O(1) dedup
    source_url = Column(String(512), nullable=True)   # Provenance URL of the raw intel
    language = Column(String(16), default="en", nullable=True)  # 'en', 'hi', 'hinglish'
    fetched_at = Column(DateTime(timezone=True), default=_utcnow)

    # Relationship
    scam_artifact = relationship("ScamArtifact", back_populates="raw_intel", uselist=False)

    __table_args__ = (
        Index("ix_raw_intel_source_time", "source", "fetched_at"),
        Index("ix_raw_intel_hash", "content_hash"),
    )


class ScamArtifact(Base):
    """Processed intelligence artifact containing ScamDNA and risk scores."""
    __tablename__ = "scam_artifacts"

    id = Column(Integer, primary_key=True, index=True)
    raw_intel_id = Column(Integer, ForeignKey("raw_intel.id", ondelete="CASCADE"), nullable=False)
    campaign_id = Column(String(32), index=True, nullable=True)

    # --- ScamDNA Core Fields ---
    scam_type = Column(String(64), index=True, nullable=False)
    confidence_score = Column(Float, default=0.0)         # AI classifier confidence (0-1)
    keywords = Column(Text, nullable=False, default="")   # Comma-separated list
    extracted_urls = Column(Text, nullable=True)           # Comma-separated list
    shortened_urls = Column(Text, nullable=True)           # Comma-separated shortened URLs
    extracted_emails = Column(Text, nullable=True)
    extracted_apks = Column(Text, nullable=True)
    extracted_handles = Column(Text, nullable=True)
    bank_references = Column(Text, nullable=True)
    wallet_addresses = Column(Text, nullable=True)
    wa_links = Column(Text, nullable=True)                 # WhatsApp wa.me/ links
    tg_links = Column(Text, nullable=True)                 # Telegram t.me/ links
    aadhaar_refs = Column(Text, nullable=True)             # Detected Aadhaar number patterns
    pan_refs = Column(Text, nullable=True)                 # Detected PAN card patterns
    ifsc_codes = Column(Text, nullable=True)               # Detected IFSC codes
    platform = Column(String(64), nullable=False)

    # --- Geographic Intelligence ---
    geo_references = Column(Text, nullable=True)           # Comma-separated location mentions
    state = Column(String(64), nullable=True, index=True)  # Primary Indian state detected
    district = Column(String(64), nullable=True, index=True)  # Primary district detected

    # --- Scoring & Status ---
    risk_score = Column(Float, default=0.0)
    status = Column(String(32), default="New", nullable=False, index=True)
    processed_at = Column(DateTime(timezone=True), default=_utcnow)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)  # type: ignore[call-overload]

    # Relationship
    raw_intel = relationship("RawIntel", back_populates="scam_artifact")
    threat_history = relationship("ThreatHistory", back_populates="scam_artifact")

    __table_args__ = (
        Index("ix_scam_artifact_campaign_risk", "campaign_id", "risk_score"),
        Index("ix_scam_artifact_type_status", "scam_type", "status"),
        Index("ix_scam_artifact_state", "state"),
        Index("ix_scam_artifact_processed_at", "processed_at"),
    )


class ThreatHistory(Base):
    """Immutable audit log of every threat detection event for compliance."""
    __tablename__ = "threat_history"

    id = Column(Integer, primary_key=True, index=True)
    scam_artifact_id = Column(Integer, ForeignKey("scam_artifacts.id", ondelete="SET NULL"), nullable=True)
    timestamp = Column(DateTime(timezone=True), default=_utcnow, index=True)
    platform = Column(String(64), nullable=False)
    scam_type = Column(String(64), nullable=False)
    risk_score = Column(Float, nullable=False)
    raw_text = Column(Text, nullable=False)
    verdict = Column(String(64), nullable=False)
    state = Column(String(64), nullable=True, index=True)
    district = Column(String(64), nullable=True)

    # Relationship
    scam_artifact = relationship("ScamArtifact", back_populates="threat_history")

    __table_args__ = (
        Index("ix_threat_history_timestamp_risk", "timestamp", "risk_score"),
        Index("ix_threat_history_state_type", "state", "scam_type"),
    )


class Campaign(Base):
    """Tracked fraud campaign cluster with aggregated intelligence."""
    __tablename__ = "campaigns"

    id = Column(Integer, primary_key=True, index=True)
    campaign_id = Column(String(32), unique=True, nullable=False, index=True)
    primary_scam_type = Column(String(64), nullable=False)
    max_risk_score = Column(Float, default=0.0)
    artifact_count = Column(Integer, default=1)
    first_seen = Column(DateTime(timezone=True), default=_utcnow)
    last_seen = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)  # type: ignore[call-overload]
    status = Column(String(32), default="Active", nullable=False)
    tags = Column(Text, nullable=True)    # JSON-serialized list of tags
    affected_states = Column(Text, nullable=True)   # Comma-separated states


class SuspectPhoneNumber(Base):
    """
    Deduplicated registry of suspect phone numbers extracted across all scam artifacts.
    Enables cross-campaign phone tracking and repeat-offender detection.
    """
    __tablename__ = "suspect_phone_numbers"

    id = Column(Integer, primary_key=True, index=True)
    phone_number = Column(String(20), unique=True, nullable=False, index=True)
    occurrence_count = Column(Integer, default=1)
    scam_types = Column(Text, nullable=True)         # Comma-separated scam types this number was seen in
    platforms = Column(Text, nullable=True)          # Comma-separated sources
    campaign_ids = Column(Text, nullable=True)       # Comma-separated campaign IDs
    first_seen = Column(DateTime(timezone=True), default=_utcnow)
    last_seen = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)  # type: ignore[call-overload]
    is_flagged = Column(Boolean, default=True)
    state = Column(String(64), nullable=True)

    __table_args__ = (
        Index("ix_suspect_phone_count", "occurrence_count"),
    )


class SuspectDomain(Base):
    """
    Deduplicated domain/URL registry with provenance, risk metadata,
    and campaign associations. Feeds directly into blocklist export.
    """
    __tablename__ = "suspect_domains"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(512), unique=True, nullable=False, index=True)
    full_url = Column(Text, nullable=True)
    occurrence_count = Column(Integer, default=1)
    max_risk_score = Column(Float, default=0.0)
    scam_types = Column(Text, nullable=True)         # Comma-separated
    campaign_ids = Column(Text, nullable=True)       # Comma-separated
    platforms = Column(Text, nullable=True)          # Comma-separated sources
    first_seen = Column(DateTime(timezone=True), default=_utcnow)
    last_seen = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)  # type: ignore[call-overload]
    is_active = Column(Boolean, default=True)
    is_shortened = Column(Boolean, default=False)    # True if bit.ly / tinyurl etc.

    __table_args__ = (
        Index("ix_suspect_domain_risk", "max_risk_score"),
        Index("ix_suspect_domain_count", "occurrence_count"),
    )


class IndiaGeoHeatmap(Base):
    """
    Pre-aggregated state/district threat counts updated after each pipeline run.
    Enables O(1) choropleth map rendering without expensive aggregation queries.
    """
    __tablename__ = "india_geo_heatmap"

    id = Column(Integer, primary_key=True, index=True)
    state = Column(String(64), unique=True, nullable=False, index=True)
    threat_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)       # Risk >= 75
    high_count = Column(Integer, default=0)           # Risk 50-74
    top_scam_type = Column(String(64), nullable=True)
    last_updated = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)  # type: ignore[call-overload]

    __table_args__ = (
        Index("ix_heatmap_state_count", "state", "threat_count"),
    )