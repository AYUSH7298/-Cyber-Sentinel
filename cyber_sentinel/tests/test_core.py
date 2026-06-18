import pytest
import asyncio
from fastapi.testclient import TestClient
from backend.main import app
from backend.security.auth import create_access_token
from backend.ai.hybrid_pipeline import HybridPipeline

# Test Client
client = TestClient(app)

# ─── Auth Tokens ─────────────────────────────────────────────
def get_admin_token():
    return create_access_token({"sub": "admin_user", "role": "admin"})

def get_user_token():
    return create_access_token({"sub": "standard_user", "role": "user"})


# ─── API Endpoint Tests ──────────────────────────────────────
def test_root_endpoint():
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Core Engine Online" in resp.json()["status"]

def test_secure_intel_unauthorized():
    # No token provided
    resp = client.get("/api/v1/secure-intel")
    assert resp.status_code == 403

def test_secure_intel_authorized():
    token = get_user_token()
    resp = client.get("/api/v1/secure-intel", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert "authenticated" in resp.json()["message"]

def test_admin_trigger_scrapers_forbidden():
    # User token does not have admin role
    token = get_user_token()
    resp = client.post("/api/v1/admin/trigger-scrapers", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403

def test_admin_trigger_scrapers_success():
    # Admin token
    token = get_admin_token()
    resp = client.post("/api/v1/admin/trigger-scrapers", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert "Massive ingestion triggered" in resp.json()["message"]


# ─── Hybrid AI Pipeline Tests ────────────────────────────────
@pytest.mark.asyncio
async def test_hybrid_pipeline_stage1_shield():
    pipeline = HybridPipeline()
    
    # Safe message should be discarded
    safe_text = "I had a great time at the park today with my dog."
    assert pipeline.stage1_local_filter(safe_text) is False
    
    # Suspicious message should be flagged
    scam_text = "URGENT! Your SBI account is blocked. Update KYC at http://fake-kyc.com"
    assert pipeline.stage1_local_filter(scam_text) is True

@pytest.mark.asyncio
async def test_hybrid_pipeline_integration():
    pipeline = HybridPipeline()
    
    # Process a safe post (should return None because it's filtered)
    safe_post = "Hey when are we meeting for dinner? Let me know."
    result = await pipeline.process_post(safe_post)
    assert result is None
