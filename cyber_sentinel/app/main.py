from fastapi import FastAPI, Depends, BackgroundTasks, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from app import models, database
from app.collectors.social_scraper import SocialScraper
from app.collectors.malware_scraper import MalwareScraper
from app.collectors.portal_scraper import PortalScraper
from app.collectors.telegram_osint import TelegramCollector
from app.ai.pipeline import AnalyticsPipeline
from app.config import settings
import asyncio
import logging
import os
from contextlib import asynccontextmanager

# ─── Logging Setup ────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ─── Application Factory ──────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Launch the background OSINT scheduler on application start."""
    logger.info("[Startup] Cyber Sentinel v%s initializing...", settings.VERSION)
    task = asyncio.create_task(_schedule_osint_pull())
    logger.info("[Startup] Background OSINT scheduler started (interval=%ds).", settings.OSINT_POLL_INTERVAL_SECONDS)
    yield
    task.cancel()

app = FastAPI(
    title="Cyber Sentinel Core Engine",
    description="AI-Powered Fraud Campaign Intelligence & Early Warning System",
    version=settings.VERSION,
    docs_url="/docs" if settings.ENVIRONMENT != "production" else None,
    redoc_url="/redoc" if settings.ENVIRONMENT != "production" else None,
    lifespan=lifespan,
)

# CORS — restrict in production to your dashboard origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8501", "http://127.0.0.1:8501"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)


# ─── Database Migrations ──────────────────────────────────────
def run_migrations():
    """Apply incremental SQLite schema migrations on startup."""
    db_file = settings.DATABASE_URL.replace("sqlite:///", "")
    if not os.path.exists(db_file):
        return

    import sqlite3
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        # v1 → v2: add status column to scam_artifacts
        cursor.execute("PRAGMA table_info(scam_artifacts);")
        columns = [col[1] for col in cursor.fetchall()]

        if columns:
            if "status" not in columns:
                cursor.execute("ALTER TABLE scam_artifacts ADD COLUMN status VARCHAR DEFAULT 'New';")
                logger.info("[Migration] Added 'status' column to scam_artifacts.")

            if "confidence_score" not in columns:
                cursor.execute("ALTER TABLE scam_artifacts ADD COLUMN confidence_score REAL DEFAULT 0.0;")
                logger.info("[Migration] Added 'confidence_score' column to scam_artifacts.")

            if "geo_references" not in columns:
                cursor.execute("ALTER TABLE scam_artifacts ADD COLUMN geo_references TEXT;")
                logger.info("[Migration] Added 'geo_references' column to scam_artifacts.")

            if "extracted_emails" not in columns:
                cursor.execute("ALTER TABLE scam_artifacts ADD COLUMN extracted_emails TEXT;")
            if "extracted_apks" not in columns:
                cursor.execute("ALTER TABLE scam_artifacts ADD COLUMN extracted_apks TEXT;")
            if "extracted_handles" not in columns:
                cursor.execute("ALTER TABLE scam_artifacts ADD COLUMN extracted_handles TEXT;")
            if "bank_references" not in columns:
                cursor.execute("ALTER TABLE scam_artifacts ADD COLUMN bank_references TEXT;")
            if "wallet_addresses" not in columns:
                cursor.execute("ALTER TABLE scam_artifacts ADD COLUMN wallet_addresses TEXT;")
                logger.info("[Migration] Added new DNA entity columns to scam_artifacts.")

        conn.commit()
        conn.close()
    except Exception as exc:
        logger.error("[Migration] Failed: %s", exc)


# ─── Startup Initialization ───────────────────────────────────
run_migrations()
models.Base.metadata.create_all(bind=database.engine)

# Singleton instances (initialized once at startup)
pipeline_worker = AnalyticsPipeline()
social_scraper = SocialScraper()
malware_scraper = MalwareScraper()
portal_scraper = PortalScraper()
telegram_collector = TelegramCollector()


def _run_pipeline_background(raw_id: int, db_session: Session):
    """Wrapper for BackgroundTasks (sync context)."""
    try:
        pipeline_worker.run_pipeline(raw_id, db_session)
    except Exception as exc:
        logger.error("[Background] Pipeline error for raw_id=%s: %s", raw_id, exc)
    finally:
        db_session.close()


def _process_unanalyzed(db: Session, background_tasks: BackgroundTasks):
    """Queue all unprocessed raw intel records for AI analysis."""
    analyzed_ids = db.query(models.ScamArtifact.raw_intel_id).subquery()
    unprocessed = (
        db.query(models.RawIntel)
        .filter(~models.RawIntel.id.in_(analyzed_ids))
        .limit(10)
        .all()
    )
    for item in unprocessed:
        # Each background task gets its own DB session to avoid threading issues
        new_session = database.SessionLocal()
        background_tasks.add_task(_run_pipeline_background, item.id, new_session)
    return len(unprocessed)


# ─── Health Check ─────────────────────────────────────────────
@app.get("/health", tags=["System"])
def health_check():
    """Container health check endpoint."""
    return {"status": "healthy", "version": settings.VERSION, "env": settings.ENVIRONMENT}


# ─── Intel Ingestion ──────────────────────────────────────────
@app.post("/api/v1/intel/manual", tags=["Intel"])
def manual_ingestion(
    text: str = Query(..., min_length=10, description="Suspicious message or threat text"),
    source: str = Query("manual", description="Source platform: telegram, rss_news, manual, etc."),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: Session = Depends(database.get_db),
):
    """Ingest a single raw intelligence item and queue AI analysis."""
    # Deduplication guard
    existing = db.query(models.RawIntel).filter(models.RawIntel.raw_text == text).first()
    if existing:
        return {"status": "duplicate", "raw_intel_id": existing.id, "message": "Record already exists."}

    raw_entry = models.RawIntel(source=source, raw_text=text)
    db.add(raw_entry)
    db.commit()
    db.refresh(raw_entry)

    new_session = database.SessionLocal()
    background_tasks.add_task(_run_pipeline_background, raw_entry.id, new_session)

    return {"status": "queued", "raw_intel_id": raw_entry.id}


# ─── Collection Triggers ──────────────────────────────────────
@app.post("/api/v1/collect/social", tags=["Collectors"])
def trigger_social_pull(
    background_tasks: BackgroundTasks,
    db: Session = Depends(database.get_db),
):
    """Trigger collection from Social Media (YouTube, Insta, FB, X)."""
    new_records = social_scraper.fetch_latest_intel(db)
    queued = _process_unanalyzed(db, background_tasks)
    return {
        "status": "success",
        "new_raw_records_collected": new_records,
        "queued_for_analysis": queued,
    }

@app.post("/api/v1/collect/malware", tags=["Collectors"])
def trigger_malware_pull(
    background_tasks: BackgroundTasks,
    db: Session = Depends(database.get_db),
):
    """Trigger collection from APK Dist sources and Phishing Domains."""
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
    """Trigger collection from Scam Reporting Portals."""
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
    """Trigger a Telegram channel scraping run and queue analysis."""
    new_records = await telegram_collector.fetch_latest_messages_async(db)
    queued = _process_unanalyzed(db, background_tasks)
    return {
        "status": "success",
        "new_raw_records_collected": new_records,
        "queued_for_analysis": queued,
    }


# ─── Analytics Endpoints ──────────────────────────────────────
@app.get("/api/v1/analytics/threat-history", tags=["Analytics"])
def get_threat_history(
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(database.get_db),
):
    """Return paginated threat detection history ordered by most recent."""
    results = (
        db.query(models.ThreatHistory)
        .order_by(models.ThreatHistory.timestamp.desc())
        .limit(limit)
        .all()
    )
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
        }
        for r in results
    ]


@app.get("/api/v1/analytics/dashboard-feed", tags=["Analytics"])
def get_dashboard_data(
    limit: int = Query(500, ge=1, le=2000),
    db: Session = Depends(database.get_db),
):
    """Return combined artifact + raw intel data for the dashboard."""
    results = (
        db.query(
            models.ScamArtifact.campaign_id,
            models.ScamArtifact.scam_type,
            models.ScamArtifact.risk_score,
            models.ScamArtifact.confidence_score,
            models.ScamArtifact.extracted_urls,
            models.ScamArtifact.status,
            models.ScamArtifact.platform,
            models.ScamArtifact.keywords,
            models.ScamArtifact.geo_references,
            models.ScamArtifact.extracted_emails,
            models.ScamArtifact.extracted_apks,
            models.ScamArtifact.extracted_handles,
            models.ScamArtifact.bank_references,
            models.ScamArtifact.wallet_addresses,
            models.RawIntel.raw_text,
            models.RawIntel.fetched_at,
        )
        .join(models.RawIntel, models.RawIntel.id == models.ScamArtifact.raw_intel_id)
        .order_by(models.RawIntel.fetched_at.desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "campaign_id": r.campaign_id or "UNCLUSTERED",
            "scam_type": r.scam_type,
            "risk_score": r.risk_score,
            "confidence": r.confidence_score,
            "urls": r.extracted_urls or "",
            "status": r.status,
            "platform": r.platform,
            "keywords": r.keywords or "",
            "geo": r.geo_references or "",
            "emails": getattr(r, "extracted_emails", ""),
            "apks": getattr(r, "extracted_apks", ""),
            "handles": getattr(r, "extracted_handles", ""),
            "bank_references": getattr(r, "bank_references", ""),
            "wallet_addresses": getattr(r, "wallet_addresses", ""),
            "text": r.raw_text,
            "timestamp": r.fetched_at.strftime("%Y-%m-%d %H:%M:%S"),
        }
        for r in results
    ]


@app.get("/api/v1/analytics/campaigns", tags=["Analytics"])
def get_campaigns(db: Session = Depends(database.get_db)):
    """Return aggregated campaign statistics."""
    from sqlalchemy import func

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


# ─── Alert Management ─────────────────────────────────────────
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


# ─── Background Scheduler ─────────────────────────────────────
async def _schedule_osint_pull():
    """Automated OSINT collection and analysis loop."""
    while True:
        await asyncio.sleep(settings.OSINT_POLL_INTERVAL_SECONDS)
        logger.info("[Scheduler] Running automated OSINT fetch cycle...")
        try:
            db = database.SessionLocal()
            soc_count = social_scraper.fetch_latest_intel(db)
            mal_count = malware_scraper.fetch_latest_intel(db)
            port_count = portal_scraper.fetch_latest_intel(db)
            tg_count = await telegram_collector.fetch_latest_messages_async(db)
            total = soc_count + mal_count + port_count + tg_count

            # Process all unanalyzed records synchronously in scheduler context
            analyzed_ids = db.query(models.ScamArtifact.raw_intel_id).subquery()
            unprocessed = (
                db.query(models.RawIntel)
                .filter(~models.RawIntel.id.in_(analyzed_ids))
                .all()
            )
            for item in unprocessed:
                pipeline_worker.run_pipeline(item.id, db)

            db.close()
            logger.info("[Scheduler] Cycle complete. Ingested=%d, Analyzed=%d", total, len(unprocessed))
        except Exception as exc:
            logger.error("[Scheduler] Error in OSINT cycle: %s", exc)

