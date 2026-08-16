"""
main.py
=======
PhishGuard FastAPI application entry point.

Initializes the application, configures middleware (CORS, security headers,
rate limiting), registers routes, and loads the ML model at startup.

Run locally with:
    uvicorn backend.main:app --reload --port 8000

Then visit:
    http://localhost:8000/docs  ← Interactive API documentation (Swagger UI)
    http://localhost:8000/api/health  ← Health check
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from backend.config import settings
from backend.logging import get_logger, setup_logging
from backend.models.schemas import HealthResponse
from backend.rate_limit import limiter
from backend.routes.analyze import router as analyze_router
from backend.services.predictor import PhishGuardPredictor


def _log_level(name: str) -> int:
    """Map a settings log-level string to a logging level."""
    return getattr(logging, name.upper(), logging.INFO)


setup_logging(level=_log_level(settings.log_level))
logger = get_logger(__name__)


# ─── App Lifespan (startup / shutdown) ───────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan context manager.

    Loads the ML model into app.state on startup so it is shared across all
    requests without reloading on every call. Any shutdown cleanup happens
    after yield.
    """
    logger.info("PhishGuard starting up...")
    app.state.predictor = PhishGuardPredictor()
    yield
    logger.info("PhishGuard shutting down.")


# ─── FastAPI Application ──────────────────────────────────────────────────────
app = FastAPI(
    title="PhishGuard API",
    description=(
        "AI-powered phishing URL detection. "
        "Submit a URL and receive a classification (PHISHING or LEGITIMATE), "
        "a confidence score, and an explanation of the top contributing features."
    ),
    version=settings.app_version,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ─── Middleware: Rate Limiting ────────────────────────────────────────────────
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# ─── Middleware: Security Headers ─────────────────────────────────────────────
@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Attach hardened security headers to every response."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), payment=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    return response


# ─── Middleware: CORS ─────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
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
_frontend_path = Path(__file__).resolve().parent.parent / "frontend"
if _frontend_path.is_dir():
    app.mount(
        "/",
        StaticFiles(directory=_frontend_path, html=True),
        name="frontend",
    )
