import logging
from fastapi import FastAPI, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from backend.security.rate_limiter import setup_rate_limiting, limiter
from backend.security.auth import verify_token, require_admin_role
from backend.api import websockets
from backend.ai.hybrid_pipeline import HybridPipeline

# Configure Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Cyber Sentinel RAKSHAK Core", version="3.0-Production")

# 1. Strict CORS Policy (Security)
app.add_middleware(
    CORSMiddleware,
    # ONLY allow the exact IP/Port of the React Frontend
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# 2. Attach Anti-DDoS Rate Limiter (Security)
setup_rate_limiting(app)

# 3. Attach WebSockets (Live Refresh)
app.include_router(websockets.router)

# 4. Initialize Hybrid AI Engine
hybrid_ai = HybridPipeline()

@app.get("/")
@limiter.limit("5/minute")
async def root(request: Request):
    return {"status": "Core Engine Online. API is protected."}

@app.get("/api/v1/secure-intel", dependencies=[Depends(verify_token)])
@limiter.limit("20/minute")
async def get_secure_intel(request: Request):
    """
    Example protected endpoint. Requires a valid JWT token.
    """
    return {"message": "You are authenticated and viewing secure threat intelligence."}

@app.post("/api/v1/admin/trigger-scrapers", dependencies=[Depends(require_admin_role)])
@limiter.limit("1/minute")
async def trigger_massive_ingestion(request: Request):
    """
    Example RBAC protected endpoint. Only ADMINs can trigger the massive 10k scraper.
    """
    return {"message": "Massive ingestion triggered successfully."}
