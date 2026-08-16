"""
rate_limit.py
=============
Rate limiting configuration for PhishGuard.

Holds the shared slowapi `Limiter` instance and the per-route limit
strings. Defined here (not in main.py) so route modules can import it
without creating a circular import.

Limits are configured via `Settings.rate_limit_per_minute`.
"""

from __future__ import annotations

from fastapi import Request
from slowapi import Limiter

from backend.config import settings


def _client_key(request: Request) -> str:
    """
    Rate-limit key for a request.

    When running behind a trusted reverse proxy (e.g. Render), use the
    first X-Forwarded-For hop so all users are keyed individually instead
    of sharing the proxy IP. Only honor the header when
    TRUST_PROXY_HEADERS is enabled to avoid client-side header spoofing.
    """
    if settings.trust_proxy_headers:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


limiter = Limiter(key_func=_client_key)


def analyze_limit() -> str:
    """Return the per-IP rate limit string for POST /api/analyze."""
    return f"{settings.rate_limit_per_minute}/minute"
