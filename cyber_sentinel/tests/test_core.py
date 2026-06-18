import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.main import app
from backend import database, models

# ─── Test Database Setup ───────────────────────────────────────
SQLALCHEMY_TEST_URL = "sqlite:///./test_cyber_sentinel.db"

test_engine = create_engine(
    SQLALCHEMY_TEST_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

models.Base.metadata.create_all(bind=test_engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[database.get_db] = override_get_db
client = TestClient(app)


# ─── Health Check ─────────────────────────────────────────────
def test_health_check():
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"


# ─── Manual Ingestion ─────────────────────────────────────────
def test_manual_ingestion_creates_record():
    resp = client.post(
        "/api/v1/intel/manual",
        params={
            "text": "WARNING: SBI KYC update required immediately. Visit http://sbi-kyc-fake.com",
            "source": "manual",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] in ("queued", "duplicate")
    assert "raw_intel_id" in data


def test_manual_ingestion_deduplication():
    """Second identical ingestion should return 'duplicate'."""
    text = "Unique test scam message for dedup testing http://scam-test-unique.com"
    client.post("/api/v1/intel/manual", params={"text": text, "source": "manual"})
    resp = client.post("/api/v1/intel/manual", params={"text": text, "source": "manual"})
    data = resp.json()
    assert data["status"] == "duplicate"


def test_manual_ingestion_too_short():
    """Ingestion of very short text should be rejected."""
    resp = client.post(
        "/api/v1/intel/manual",
        params={"text": "short", "source": "manual"},
    )
    assert resp.status_code == 422   # FastAPI validation error


# ─── Dashboard Feed ───────────────────────────────────────────
def test_dashboard_feed_returns_list():
    resp = client.get("/api/v1/analytics/dashboard-feed")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_threat_history_returns_list():
    resp = client.get("/api/v1/analytics/threat-history")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


# ─── Alert Status Update ──────────────────────────────────────
def test_alert_status_update_invalid_status():
    resp = client.put(
        "/api/v1/alerts/CAMP_001/status",
        params={"status": "INVALID_STATUS"},
    )
    assert resp.status_code == 422


def test_alert_status_update_not_found():
    resp = client.put(
        "/api/v1/alerts/NONEXISTENT_CAMPAIGN/status",
        params={"status": "Acknowledged"},
    )
    assert resp.status_code == 404


# ─── AI Unit Tests ────────────────────────────────────────────
from backend.ai.classifier import ScamClassifier
from backend.ai.dna_extractor import DNAExtractor
from backend.ai.clusterer import CampaignClusterer


def test_classifier_returns_tuple():
    clf = ScamClassifier()
    label, confidence = clf.classify_text(
        "Dear SBI user, your account is blocked. Update KYC at http://sbi-kyc-fake.com"
    )
    assert isinstance(label, str)
    assert 0.0 <= confidence <= 1.0


def test_classifier_safe_url_only():
    clf = ScamClassifier()
    label, conf = clf.classify_text("https://google.com")
    assert label == "Safe / Non-Scam"


def test_dna_extractor_extracts_url():
    extractor = DNAExtractor()
    dna = extractor.extract_dna("Click http://fake-kyc-sbi.com to update your KYC now!")
    assert len(dna["urls"]) >= 1
    assert any("fake-kyc-sbi.com" in u for u in dna["urls"])


def test_dna_extractor_phone_number():
    extractor = DNAExtractor()
    dna = extractor.extract_dna("Call us at +91 9876543210 for your loan")
    assert len(dna["phone_numbers"]) >= 1


def test_dna_extractor_geo_references():
    extractor = DNAExtractor()
    dna = extractor.extract_dna("Fraud reported in Sector 56, Gurugram Haryana")
    assert len(dna["geo_references"]) >= 1


def test_risk_score_range():
    extractor = DNAExtractor()
    score = extractor.compute_risk("Phishing", 3, 5, phone_count=2, psych_count=4, confidence=0.9)
    assert 0.0 <= score <= 100.0


def test_clusterer_creates_new_campaign_when_empty():
    clusterer = CampaignClusterer()
    cid, score = clusterer.resolve_campaign("Some scam text", [])
    assert cid == "CAMP_001"


def test_clusterer_sequential_campaign_ids():
    clusterer = CampaignClusterer()
    existing = [
        {"campaign_id": "CAMP_001", "text": "loan scam whatsapp deposit"},
        {"campaign_id": "CAMP_002", "text": "investment crypto guaranteed returns"},
    ]
    cid, score = clusterer.resolve_campaign(
        "Totally different sextortion blackmail video", existing, threshold=0.99
    )
    assert cid == "CAMP_003"
