"""
main.py
=======
PhishGuard FastAPI application entry point.

Initializes the application, configures middleware (CORS, rate limiting),
registers routes, and loads the ML model at startup.

Run locally with:
    uvicorn backend.main:app --reload --port 8000

Then visit:
    http://localhost:8000/docs  ← Interactive API documentation (Swagger UI)
    http://localhost:8000/api/health  ← Health check
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from backend.models.schemas import HealthResponse
from backend.routes.analyze import router as analyze_router
from backend.services.predictor import PhishGuardPredictor

# Load environment variables from .env file (if present)
load_dotenv()

# ─── Rate Limiter ─────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

# ─── App Lifespan (startup / shutdown) ───────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan context manager.

    Runs on startup: loads the ML model into app.state so it is shared
    across all requests without reloading on every call.

    Runs on shutdown: any cleanup if needed.
    """
    print("[PhishGuard] Starting up...")
    app.state.predictor = PhishGuardPredictor()
    yield
    print("[PhishGuard] Shutting down.")


# ─── FastAPI Application ──────────────────────────────────────────────────────
app = FastAPI(
    title="PhishGuard API",
    description=(
        "AI-powered phishing URL detection. "
        "Submit a URL and receive a classification (PHISHING or LEGITIMATE), "
        "a confidence score, and an explanation of the top contributing features."
    ),
    version=os.getenv("APP_VERSION", "1.0.0"),
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ─── Middleware: Rate Limiting ────────────────────────────────────────────────
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ─── Middleware: CORS ─────────────────────────────────────────────────────────
_cors_origins_raw = os.getenv("CORS_ORIGINS", "*")
_cors_origins = [o.strip() for o in _cors_origins_raw.split(",")]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Accept"],
)

# ─── Routes ───────────────────────────────────────────────────────────────────
app.include_router(analyze_router, prefix="/api", tags=["Analysis"])


@app.get(
    "/api/health",
    response_model=HealthResponse,
    tags=["Health"],
    summary="Health check",
    description="Returns the service status and whether the ML model is loaded.",
)
async def health_check(request: Request) -> HealthResponse:
    """Check service health and model status."""
    predictor = request.app.state.predictor
    return HealthResponse(
        status="ok" if predictor.is_loaded else "degraded",
        model_loaded=predictor.is_loaded,
        version=app.version,
    )


# ─── Serve Frontend Static Files ──────────────────────────────────────────────
# In production, the frontend static files are served directly by FastAPI.
# This allows deploying a single service to Render instead of two separate services.
_frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.isdir(_frontend_path):
    app.mount("/", StaticFiles(directory=_frontend_path, html=True), name="frontend")
