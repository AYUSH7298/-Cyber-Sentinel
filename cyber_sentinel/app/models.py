from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text, Index
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
    source = Column(String(64), nullable=False, index=True)   # 'telegram', 'rss_news', 'manual'
    raw_text = Column(Text, nullable=False)
    fetched_at = Column(DateTime(timezone=True), default=_utcnow)

    # Relationship
    scam_artifact = relationship("ScamArtifact", back_populates="raw_intel", uselist=False)

    # Composite index for dedup lookups
    __table_args__ = (
        Index("ix_raw_intel_source_text", "source", "fetched_at"),
    )


class ScamArtifact(Base):
    """Processed intelligence artifact containing ScamDNA and risk scores."""
    __tablename__ = "scam_artifacts"

    id = Column(Integer, primary_key=True, index=True)
    raw_intel_id = Column(Integer, ForeignKey("raw_intel.id", ondelete="CASCADE"), nullable=False)
    campaign_id = Column(String(32), index=True, nullable=True)

    # --- ScamDNA Fields ---
    scam_type = Column(String(64), index=True, nullable=False)
    confidence_score = Column(Float, default=0.0)         # AI classifier confidence (0-1)
    keywords = Column(Text, nullable=False, default="")   # Comma-separated list
    extracted_urls = Column(Text, nullable=True)           # Comma-separated list
    extracted_emails = Column(Text, nullable=True)
    extracted_apks = Column(Text, nullable=True)
    extracted_handles = Column(Text, nullable=True)
    bank_references = Column(Text, nullable=True)
    wallet_addresses = Column(Text, nullable=True)
    platform = Column(String(64), nullable=False)

    # --- Geographic Intelligence ---
    geo_references = Column(Text, nullable=True)           # Comma-separated location mentions

    # --- Scoring & Status ---
    risk_score = Column(Float, default=0.0)
    status = Column(String(32), default="New", nullable=False, index=True)
    processed_at = Column(DateTime(timezone=True), default=_utcnow)

    # Relationship
    raw_intel = relationship("RawIntel", back_populates="scam_artifact")
    threat_history = relationship("ThreatHistory", back_populates="scam_artifact")

    __table_args__ = (
        Index("ix_scam_artifact_campaign_risk", "campaign_id", "risk_score"),
        Index("ix_scam_artifact_type_status", "scam_type", "status"),
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

    # Relationship
    scam_artifact = relationship("ScamArtifact", back_populates="threat_history")

    __table_args__ = (
        Index("ix_threat_history_timestamp_risk", "timestamp", "risk_score"),
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
    last_seen = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
    status = Column(String(32), default="Active", nullable=False)
    tags = Column(Text, nullable=True)   # JSON-serialized list of tags