from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker
from .config import settings
import logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------
# Engine Creation
# ---------------------------------------------------------------
connect_args = {}

if settings.DATABASE_URL.startswith("sqlite"):
    # SQLite-specific: disable same-thread check for FastAPI async context
    connect_args["check_same_thread"] = False

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    # Connection pool tuning for production (ignored by SQLite)
    pool_pre_ping=True,           # Verify connections before checkout
    pool_recycle=3600,            # Recycle connections every 1 hour
    echo=(settings.ENVIRONMENT == "development"),   # Log SQL in dev only
)

# Enable WAL mode for SQLite to allow concurrent reads during writes
if settings.DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_conn, connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """FastAPI dependency: yields a database session and guarantees cleanup."""
    db = SessionLocal()
    try:
        yield db
    except Exception as exc:
        logger.error("Database session error: %s", exc)
        db.rollback()
        raise
    finally:
        db.close()