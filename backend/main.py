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
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from backend.config import settings
from backend.logging import get_logger, setup_logging
from backend.models.schemas import HealthResponse
from backend.rate_limit import limiter
from backend.routes.analyze import router as analyze_router
from backend.routes.features import router as features_router
from backend.services.predictor import PhishGuardPredictor


def _log_level(name: str) -> int:
    """Map a settings log-level string to a logging level."""
    return getattr(logging, name.upper(), logging.INFO)


def _build_csp(docs_enabled: bool) -> str:
    """
    Build a Content-Security-Policy string.

    The default policy is strict: only self-hosted scripts, Google Fonts, and
    same-origin API calls. When interactive docs are enabled, the policy is
    relaxed to allow the Swagger UI / ReDoc CDN assets.
    """
    directives = [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "img-src 'self' data:",
        "font-src 'self' https://fonts.gstatic.com",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
    ]
    if docs_enabled:
        directives[1] += " 'unsafe-inline' https://cdn.jsdelivr.net"
        directives[2] += " https://cdn.jsdelivr.net"
        directives[3] += " https://fastapi.tiangolo.com"
    return "; ".join(directives)


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
    # Interactive docs are gated: disabled in production to avoid exposing the
    # API surface to reconnaissance (see Settings.docs_enabled).
    docs_url="/docs" if settings.docs_enabled else None,
    redoc_url="/redoc" if settings.docs_enabled else None,
    openapi_url="/openapi.json" if settings.docs_enabled else None,
)

# ─── Middleware: Rate Limiting ────────────────────────────────────────────────
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# ─── Middleware: Trusted Hosts ────────────────────────────────────────────────
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.trusted_host_list,
)


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
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = _build_csp(settings.docs_enabled)

    # HSTS only when the client connection is HTTPS (directly or via a trusted
    # reverse proxy that forwards X-Forwarded-Proto). Browsers ignore HSTS over
    # plain HTTP, so honoring the header here cannot cause a downgrade.
    if settings.hsts_enabled:
        is_secure = request.url.scheme == "https"
        if not is_secure and settings.trust_proxy_headers:
            is_secure = request.headers.get("X-Forwarded-Proto", "").lower() == "https"
        if is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    # API responses must never be cached by intermediate proxies.
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"

    return response


# ─── Middleware: CORS ─────────────────────────────────────────────────────────
_cors_origins = settings.cors_origin_list
if settings.app_env == "production" and "*" in _cors_origins:
    logger.warning(
        "CORS is set to '*' in production. The wildcard is ignored; API calls "
        "will be same-origin only. Set CORS_ORIGINS to your frontend origin."
    )
    _cors_origins = [o for o in _cors_origins if o != "*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Accept"],
)

# ─── Routes ───────────────────────────────────────────────────────────────────
app.include_router(analyze_router, prefix="/api", tags=["Analysis"])
app.include_router(features_router, prefix="/api", tags=["Features"])


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
