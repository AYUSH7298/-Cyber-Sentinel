from fastapi import FastAPI, Depends, BackgroundTasks, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import func
from backend import models, database
from backend.collectors.social_scraper import SocialScraper
from backend.collectors.malware_scraper import MalwareScraper
from backend.collectors.portal_scraper import PortalScraper
from backend.collectors.rss_scraper import RSSCollector
from backend.collectors.telegram_osint import TelegramCollector
from backend.ai.pipeline import AnalyticsPipeline
from backend.config import settings
import asyncio
import logging
import os
import sqlite3
from contextlib import asynccontextmanager

# ─── Logging Setup ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


# ─── Database Migrations ──────────────────────────────────────────────────────
def run_migrations():
    """
    Apply incremental SQLite schema migrations on startup.
    Gracefully adds new columns without losing existing data.
    """
    db_file = settings.DATABASE_URL.replace("sqlite:///./", "./").replace("sqlite:///", "")
    if not os.path.exists(db_file):
        return

    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        # ── raw_intel migrations ──────────────────────────────────────────────
        cursor.execute("PRAGMA table_info(raw_intel);")
        raw_cols = [col[1] for col in cursor.fetchall()]
        if raw_cols:
            _add_col_if_missing(cursor, "raw_intel", "content_hash", "VARCHAR(64)", raw_cols)
            _add_col_if_missing(cursor, "raw_intel", "source_url", "VARCHAR(512)", raw_cols)
            _add_col_if_missing(cursor, "raw_intel", "language", "VARCHAR(16) DEFAULT 'en'", raw_cols)

        # ── scam_artifacts migrations ─────────────────────────────────────────
        cursor.execute("PRAGMA table_info(scam_artifacts);")
        art_cols = [col[1] for col in cursor.fetchall()]
        if art_cols:
            _add_col_if_missing(cursor, "scam_artifacts", "status", "VARCHAR DEFAULT 'New'", art_cols)
            _add_col_if_missing(cursor, "scam_artifacts", "confidence_score", "REAL DEFAULT 0.0", art_cols)
            _add_col_if_missing(cursor, "scam_artifacts", "geo_references", "TEXT", art_cols)
            _add_col_if_missing(cursor, "scam_artifacts", "extracted_emails", "TEXT", art_cols)
            _add_col_if_missing(cursor, "scam_artifacts", "extracted_apks", "TEXT", art_cols)
            _add_col_if_missing(cursor, "scam_artifacts", "extracted_handles", "TEXT", art_cols)
            _add_col_if_missing(cursor, "scam_artifacts", "bank_references", "TEXT", art_cols)
            _add_col_if_missing(cursor, "scam_artifacts", "wallet_addresses", "TEXT", art_cols)
            # v3.0 new columns
            _add_col_if_missing(cursor, "scam_artifacts", "shortened_urls", "TEXT", art_cols)
            _add_col_if_missing(cursor, "scam_artifacts", "wa_links", "TEXT", art_cols)
            _add_col_if_missing(cursor, "scam_artifacts", "tg_links", "TEXT", art_cols)
            _add_col_if_missing(cursor, "scam_artifacts", "aadhaar_refs", "TEXT", art_cols)
            _add_col_if_missing(cursor, "scam_artifacts", "pan_refs", "TEXT", art_cols)
            _add_col_if_missing(cursor, "scam_artifacts", "ifsc_codes", "TEXT", art_cols)
            _add_col_if_missing(cursor, "scam_artifacts", "state", "VARCHAR(64)", art_cols)
            _add_col_if_missing(cursor, "scam_artifacts", "district", "VARCHAR(64)", art_cols)
            _add_col_if_missing(cursor, "scam_artifacts", "updated_at", "DATETIME", art_cols)

        # ── threat_history migrations ─────────────────────────────────────────
        cursor.execute("PRAGMA table_info(threat_history);")
        hist_cols = [col[1] for col in cursor.fetchall()]
        if hist_cols:
            _add_col_if_missing(cursor, "threat_history", "state", "VARCHAR(64)", hist_cols)
            _add_col_if_missing(cursor, "threat_history", "district", "VARCHAR(64)", hist_cols)

        # ── campaigns migrations ──────────────────────────────────────────────
        cursor.execute("PRAGMA table_info(campaigns);")
        camp_cols = [col[1] for col in cursor.fetchall()]
        if camp_cols:
            _add_col_if_missing(cursor, "campaigns", "affected_states", "TEXT", camp_cols)

        conn.commit()
        conn.close()
        logger.info("[Migration] Schema migration complete.")

    except Exception as exc:
        logger.error("[Migration] Failed: %s", exc)


def _add_col_if_missing(cursor, table: str, col: str, col_type: str, existing_cols: list):
    if col not in existing_cols:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_type};")
        logger.info("[Migration] Added column '%s' to %s.", col, table)


# ─── Application Factory ──────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Launch background OSINT scheduler on startup."""
    logger.info("[Startup] Cyber Sentinel v%s initializing...", settings.VERSION)
    task = asyncio.create_task(_schedule_osint_pull())
    logger.info(
        "[Startup] Background scheduler started (interval=%ds).",
        settings.OSINT_POLL_INTERVAL_SECONDS
    )
    yield
    task.cancel()


app = FastAPI(
    title="Cyber Sentinel Core Engine",
    description="AI-Powered Fraud Campaign Intelligence & Pan-India Early Warning System v3.0",
    version=settings.VERSION,
    docs_url="/docs" if settings.ENVIRONMENT != "production" else None,
    redoc_url="/redoc" if settings.ENVIRONMENT != "production" else None,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8501", "http://127.0.0.1:8501"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)


# ─── Startup Initialization ───────────────────────────────────────────────────
run_migrations()
models.Base.metadata.create_all(bind=database.engine)

# Singleton instances (initialized once at startup)
pipeline_worker = AnalyticsPipeline()
social_scraper = SocialScraper()
malware_scraper = MalwareScraper()
portal_scraper = PortalScraper()
rss_collector = RSSCollector()
telegram_collector = TelegramCollector()


def _run_pipeline_background(raw_id: int, db_session: Session):
    """Wrapper for BackgroundTasks (sync context)."""
    try:
        pipeline_worker.run_pipeline(raw_id, db_session)
    except Exception as exc:
        logger.error("[Background] Pipeline error for raw_id=%s: %s", raw_id, exc)
    finally:
        db_session.close()


def _process_unanalyzed(db: Session, background_tasks: BackgroundTasks) -> int:
    """Queue all unprocessed raw intel records for AI analysis."""
    analyzed_ids = db.query(models.ScamArtifact.raw_intel_id).subquery()
    unprocessed = (
        db.query(models.RawIntel)
        .filter(~models.RawIntel.id.in_(analyzed_ids))
        .limit(20)
        .all()
    )
    for item in unprocessed:
        new_session = database.SessionLocal()
        background_tasks.add_task(_run_pipeline_background, item.id, new_session)
    return len(unprocessed)


# ─── Health Check ─────────────────────────────────────────────────────────────
@app.get("/health", tags=["System"])
def health_check():
    """Container health check endpoint."""
    return {
        "status": "healthy",
        "version": settings.VERSION,
        "env": settings.ENVIRONMENT,
        "scanner_feeds": {
            "rss_feeds_count": len(settings.rss_feed_urls_list),
            "telegram_channels": len(settings.telegram_channels_list),
            "reddit_subreddits": len(settings.reddit_subreddits_list),
        }
    }


# ─── Intel Ingestion ──────────────────────────────────────────────────────────
@app.post("/api/v1/intel/manual", tags=["Intel"])
def manual_ingestion(
    text: str = Query(..., min_length=10, description="Suspicious message or threat text"),
    source: str = Query("manual", description="Source platform: telegram, rss, reddit, manual, etc."),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: Session = Depends(database.get_db),
):
    """Ingest a single raw intelligence item and queue AI analysis."""
    import hashlib
    content_hash = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()

    # O(1) dedup via content_hash
    existing = db.query(models.RawIntel).filter(models.RawIntel.content_hash == content_hash).first()
    if existing:
        return {"status": "duplicate", "raw_intel_id": existing.id, "message": "Record already exists."}

    raw_entry = models.RawIntel(source=source, raw_text=text, content_hash=content_hash)
    db.add(raw_entry)
    db.commit()
    db.refresh(raw_entry)

    new_session = database.SessionLocal()
    background_tasks.add_task(_run_pipeline_background, raw_entry.id, new_session)

    return {"status": "queued", "raw_intel_id": raw_entry.id}


# ─── Collection Triggers ──────────────────────────────────────────────────────
@app.post("/api/v1/collect/rss", tags=["Collectors"])
def trigger_rss_pull(
    background_tasks: BackgroundTasks,
    db: Session = Depends(database.get_db),
):
    """Trigger real RSS/Atom feed collection from 60+ India-targeted news feeds."""
    new_records = rss_collector.fetch_latest_intel(db)
    queued = _process_unanalyzed(db, background_tasks)
    return {
        "status": "success",
        "new_raw_records_collected": new_records,
        "queued_for_analysis": queued,
        "feeds_scanned": len(settings.rss_feed_urls_list),
    }


@app.post("/api/v1/collect/social", tags=["Collectors"])
def trigger_social_pull(
    background_tasks: BackgroundTasks,
    db: Session = Depends(database.get_db),
):
    """Trigger collection from Reddit public API (India cybercrime subreddits)."""
    new_records = social_scraper.fetch_latest_intel(db)
    queued = _process_unanalyzed(db, background_tasks)
    return {
        "status": "success",
        "new_raw_records_collected": new_records,
        "queued_for_analysis": queued,
        "subreddits_scanned": len(settings.reddit_subreddits_list),
    }


@app.post("/api/v1/collect/reddit", tags=["Collectors"])
def trigger_reddit_pull(
    background_tasks: BackgroundTasks,
    db: Session = Depends(database.get_db),
):
    """Alias for /collect/social — Reddit OSINT collector."""
    return trigger_social_pull(background_tasks, db)


@app.post("/api/v1/collect/malware", tags=["Collectors"])
def trigger_malware_pull(
    background_tasks: BackgroundTasks,
    db: Session = Depends(database.get_db),
):
    """Trigger collection from URLhaus, OpenPhish threat intelligence feeds."""
    new_records = malware_scraper.fetch_latest_intel(db)
    queued = _process_unanalyzed(db, background_tasks)
    return {
        "status": "success",
        "new_raw_records_collected": new_records,
        "queued_for_analysis": queued,
    }


@app.post("/api/v1/collect/portal", tags=["Collectors"])
def trigger_portal_pull(
    background_tasks: BackgroundTasks,
    db: Session = Depends(database.get_db),
):
    """Trigger collection from CERT-In, PIB/MHA, and state police cyber cell advisories."""
    new_records = portal_scraper.fetch_latest_intel(db)
    queued = _process_unanalyzed(db, background_tasks)
    return {
        "status": "success",
        "new_raw_records_collected": new_records,
        "queued_for_analysis": queued,
    }


@app.post("/api/v1/collect/telegram", tags=["Collectors"])
async def trigger_telegram_pull(
    background_tasks: BackgroundTasks,
    db: Session = Depends(database.get_db),
):
    """Trigger a Telegram public channel scraping run and queue analysis."""
    new_records = await telegram_collector.fetch_latest_messages_async(db)
    queued = _process_unanalyzed(db, background_tasks)
    return {
        "status": "success",
        "new_raw_records_collected": new_records,
        "queued_for_analysis": queued,
        "channels_monitored": len(settings.telegram_channels_list),
    }


# ─── Analytics Endpoints ──────────────────────────────────────────────────────
@app.get("/api/v1/analytics/threat-history", tags=["Analytics"])
def get_threat_history(
    limit: int = Query(100, ge=1, le=1000),
    after_id: int = Query(0, ge=0, description="Cursor: return records with id > after_id"),
    state: str = Query("", description="Filter by Indian state name"),
    db: Session = Depends(database.get_db),
):
    """Return paginated threat detection history, ordered by most recent."""
    query = db.query(models.ThreatHistory).order_by(models.ThreatHistory.timestamp.desc())

    if after_id > 0:
        query = query.filter(models.ThreatHistory.id > after_id)
    if state:
        query = query.filter(models.ThreatHistory.state == state)

    results = query.limit(limit).all()
    return [
        {
            "id": r.id,
            "artifact_id": r.scam_artifact_id,
            "timestamp": r.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "platform": r.platform,
            "scam_type": r.scam_type,
            "risk_score": r.risk_score,
            "raw_text": r.raw_text,
            "verdict": r.verdict,
            "state": r.state,
            "district": r.district,
        }
        for r in results
    ]


@app.get("/api/v1/analytics/dashboard-feed", tags=["Analytics"])
def get_dashboard_data(
    limit: int = Query(500, ge=1, le=2000),
    after_id: int = Query(0, ge=0, description="Cursor: return records with raw_intel.id > after_id"),
    db: Session = Depends(database.get_db),
):
    """Return combined artifact + raw intel data for the dashboard."""
    query = (
        db.query(
            models.ScamArtifact.id.label("artifact_id"),
            models.ScamArtifact.campaign_id,
            models.ScamArtifact.scam_type,
            models.ScamArtifact.risk_score,
            models.ScamArtifact.confidence_score,
            models.ScamArtifact.extracted_urls,
            models.ScamArtifact.shortened_urls,
            models.ScamArtifact.status,
            models.ScamArtifact.platform,
            models.ScamArtifact.keywords,
            models.ScamArtifact.geo_references,
            models.ScamArtifact.state,
            models.ScamArtifact.district,
            models.ScamArtifact.extracted_emails,
            models.ScamArtifact.extracted_apks,
            models.ScamArtifact.extracted_handles,
            models.ScamArtifact.bank_references,
            models.ScamArtifact.wallet_addresses,
            models.ScamArtifact.wa_links,
            models.ScamArtifact.tg_links,
            models.RawIntel.id.label("raw_id"),
            models.RawIntel.raw_text,
            models.RawIntel.fetched_at,
            models.RawIntel.source_url,
        )
        .join(models.RawIntel, models.RawIntel.id == models.ScamArtifact.raw_intel_id)
        .order_by(models.RawIntel.fetched_at.desc())
    )

    if after_id > 0:
        query = query.filter(models.RawIntel.id > after_id)

    results = query.limit(limit).all()

    return [
        {
            "artifact_id": r.artifact_id,
            "campaign_id": r.campaign_id or "UNCLUSTERED",
            "scam_type": r.scam_type,
            "risk_score": r.risk_score,
            "confidence": r.confidence_score,
            "urls": r.extracted_urls or "",
            "shortened_urls": r.shortened_urls or "",
            "status": r.status,
            "platform": r.platform,
            "keywords": r.keywords or "",
            "geo": r.geo_references or "",
            "state": r.state or "",
            "district": r.district or "",
            "emails": getattr(r, "extracted_emails", "") or "",
            "apks": getattr(r, "extracted_apks", "") or "",
            "handles": getattr(r, "extracted_handles", "") or "",
            "bank_references": getattr(r, "bank_references", "") or "",
            "wallet_addresses": getattr(r, "wallet_addresses", "") or "",
            "wa_links": getattr(r, "wa_links", "") or "",
            "tg_links": getattr(r, "tg_links", "") or "",
            "text": r.raw_text,
            "timestamp": r.fetched_at.strftime("%Y-%m-%d %H:%M:%S"),
            "source_url": r.source_url or "",
        }
        for r in results
    ]


@app.get("/api/v1/analytics/campaigns", tags=["Analytics"])
def get_campaigns(db: Session = Depends(database.get_db)):
    """Return aggregated campaign statistics."""
    results = (
        db.query(
            models.ScamArtifact.campaign_id,
            func.count(models.ScamArtifact.id).label("count"),
            func.max(models.ScamArtifact.risk_score).label("max_risk"),
            func.min(models.RawIntel.fetched_at).label("first_seen"),
            func.max(models.RawIntel.fetched_at).label("last_seen"),
        )
        .join(models.RawIntel, models.RawIntel.id == models.ScamArtifact.raw_intel_id)
        .filter(models.ScamArtifact.campaign_id.isnot(None))
        .group_by(models.ScamArtifact.campaign_id)
        .order_by(func.max(models.ScamArtifact.risk_score).desc())
        .all()
    )

    return [
        {
            "campaign_id": r.campaign_id,
            "artifact_count": r.count,
            "max_risk_score": r.max_risk,
            "first_seen": r.first_seen.strftime("%Y-%m-%d %H:%M:%S") if r.first_seen else None,
            "last_seen": r.last_seen.strftime("%Y-%m-%d %H:%M:%S") if r.last_seen else None,
        }
        for r in results
    ]


@app.get("/api/v1/analytics/india-heatmap", tags=["Analytics"])
def get_india_heatmap(db: Session = Depends(database.get_db)):
    """
    Return state-level threat counts for India choropleth map rendering.
    Falls back to live aggregation if heatmap table is empty.
    """
    # Try pre-aggregated heatmap table first (fast path)
    heatmap_rows = db.query(models.IndiaGeoHeatmap).all()

    if heatmap_rows:
        return [
            {
                "state": row.state,
                "threat_count": row.threat_count,
                "critical_count": row.critical_count,
                "high_count": row.high_count,
                "top_scam_type": row.top_scam_type,
                "last_updated": row.last_updated.strftime("%Y-%m-%d %H:%M:%S") if row.last_updated else None,
            }
            for row in sorted(heatmap_rows, key=lambda x: x.threat_count, reverse=True)
        ]

    # Fallback: live aggregation from scam_artifacts
    results = (
        db.query(
            models.ScamArtifact.state,
            func.count(models.ScamArtifact.id).label("threat_count"),
        )
        .filter(models.ScamArtifact.state.isnot(None))
        .group_by(models.ScamArtifact.state)
        .order_by(func.count(models.ScamArtifact.id).desc())
        .all()
    )

    return [
        {"state": r.state, "threat_count": r.threat_count, "critical_count": 0, "high_count": 0, "top_scam_type": None}
        for r in results
        if r.state
    ]


@app.get("/api/v1/analytics/suspect-phones", tags=["Analytics"])
def get_suspect_phones(
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(database.get_db),
):
    """Return ranked suspect phone number registry for cross-campaign tracking."""
    results = (
        db.query(models.SuspectPhoneNumber)
        .order_by(models.SuspectPhoneNumber.occurrence_count.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "phone_number": r.phone_number,
            "occurrence_count": r.occurrence_count,
            "scam_types": r.scam_types,
            "platforms": r.platforms,
            "campaign_ids": r.campaign_ids,
            "state": r.state,
            "first_seen": r.first_seen.strftime("%Y-%m-%d %H:%M:%S") if r.first_seen else None,
            "last_seen": r.last_seen.strftime("%Y-%m-%d %H:%M:%S") if r.last_seen else None,
        }
        for r in results
    ]


@app.get("/api/v1/analytics/suspect-domains", tags=["Analytics"])
def get_suspect_domains(
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(database.get_db),
):
    """Return domain blocklist registry with provenance metadata."""
    results = (
        db.query(models.SuspectDomain)
        .order_by(models.SuspectDomain.max_risk_score.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "domain": r.domain,
            "full_url": r.full_url,
            "occurrence_count": r.occurrence_count,
            "max_risk_score": r.max_risk_score,
            "scam_types": r.scam_types,
            "campaign_ids": r.campaign_ids,
            "is_shortened": r.is_shortened,
            "first_seen": r.first_seen.strftime("%Y-%m-%d %H:%M:%S") if r.first_seen else None,
            "last_seen": r.last_seen.strftime("%Y-%m-%d %H:%M:%S") if r.last_seen else None,
        }
        for r in results
    ]


@app.get("/api/v1/analytics/trends", tags=["Analytics"])
def get_threat_trends(
    days: int = Query(30, ge=1, le=365, description="Number of days to look back"),
    db: Session = Depends(database.get_db),
):
    """Return daily threat counts for time-series trend charts."""
    from datetime import datetime, timedelta, timezone

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    results = (
        db.query(
            func.date(models.ThreatHistory.timestamp).label("date"),
            func.count(models.ThreatHistory.id).label("count"),
            func.avg(models.ThreatHistory.risk_score).label("avg_risk"),
        )
        .filter(models.ThreatHistory.timestamp >= cutoff)
        .group_by(func.date(models.ThreatHistory.timestamp))
        .order_by(func.date(models.ThreatHistory.timestamp).asc())
        .all()
    )

    return [
        {
            "date": str(r.date),
            "threat_count": r.count,
            "avg_risk_score": round(float(r.avg_risk or 0), 1),
        }
        for r in results
    ]


# ─── Alert Management ─────────────────────────────────────────────────────────
@app.put("/api/v1/alerts/{campaign_id}/status", tags=["Alerts"])
def update_alert_status(
    campaign_id: str,
    status: str = Query(..., pattern="^(New|Acknowledged|Resolved)$"),
    db: Session = Depends(database.get_db),
):
    """Update the case management status of all artifacts in a campaign."""
    artifacts = (
        db.query(models.ScamArtifact)
        .filter(models.ScamArtifact.campaign_id == campaign_id)
        .all()
    )
    if not artifacts:
        raise HTTPException(status_code=404, detail=f"Campaign '{campaign_id}' not found.")

    for art in artifacts:
        art.status = status
    db.commit()

    return {
        "status": "success",
        "updated_campaign": campaign_id,
        "new_status": status,
        "artifacts_updated": len(artifacts),
    }


# ─── Background Scheduler ─────────────────────────────────────────────────────
async def _schedule_osint_pull():
    """
    Automated OSINT collection and analysis loop.
    Runs all collectors in sequence on a configurable interval.
    Uses asyncio.sleep (crash-resilient with lifespan cancellation).
    """
    cycle = 0
    while True:
        await asyncio.sleep(settings.OSINT_POLL_INTERVAL_SECONDS)
        cycle += 1
        logger.info("[Scheduler] Starting automated OSINT cycle #%d...", cycle)

        try:
            db = database.SessionLocal()

            # Run all real collectors
            counts = {
                "rss": rss_collector.fetch_latest_intel(db),
                "social": social_scraper.fetch_latest_intel(db),
                "malware": malware_scraper.fetch_latest_intel(db),
                "portal": portal_scraper.fetch_latest_intel(db),
            }

            # Telegram (async)
            try:
                tg_count = await telegram_collector.fetch_latest_messages_async(db)
                counts["telegram"] = tg_count
            except Exception as exc:
                logger.warning("[Scheduler] Telegram collection error: %s", exc)
                counts["telegram"] = 0

            total_new = sum(counts.values())

            # Process all unanalyzed records (capped per cycle)
            analyzed_ids = db.query(models.ScamArtifact.raw_intel_id).subquery()
            unprocessed = (
                db.query(models.RawIntel)
                .filter(~models.RawIntel.id.in_(analyzed_ids))
                .limit(50)
                .all()
            )
            for item in unprocessed:
                item_session = database.SessionLocal()
                try:
                    pipeline_worker.run_pipeline(item.id, item_session)
                except Exception as exc:
                    logger.error("[Scheduler] Pipeline error on id=%s: %s", item.id, exc)
                finally:
                    item_session.close()

            db.close()
            logger.info(
                "[Scheduler] Cycle #%d complete. Ingested=%d (RSS=%d, Social=%d, Malware=%d, Portal=%d, TG=%d), Analyzed=%d",
                cycle, total_new,
                counts.get("rss", 0), counts.get("social", 0),
                counts.get("malware", 0), counts.get("portal", 0),
                counts.get("telegram", 0), len(unprocessed),
            )

        except Exception as exc:
            logger.error("[Scheduler] Cycle #%d error: %s", cycle, exc)
