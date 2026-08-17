"""
config.py
=========
Single source of truth for PhishGuard configuration.

All environment-driven settings live here via `pydantic-settings`.
Modules must import `settings` from this module instead of calling
`os.getenv` directly. Values are read from a `.env` file when present
and overridden by real environment variables.

Usage:
    from backend.config import settings
    settings.rate_limit_per_minute   # -> 60
"""

from __future__ import annotations

from functools import lru_cache
from ipaddress import ip_address, ip_network

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment / .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ─── Application ─────────────────────────────────────────
    app_env: str = "development"  # development | production | test
    app_version: str = "1.0.0"

    # ─── API / CORS ──────────────────────────────────────────
    cors_origins: str = "*"  # comma-separated origin list
    rate_limit_per_minute: int = 60  # max POST /api/analyze calls / min / IP
    trust_proxy_headers: bool = False  # trust X-Forwarded-For (behind Render, set True)

    # ─── Security ────────────────────────────────────────────
    # Interactive API docs (/docs, /redoc, /openapi.json). Disable in
    # production to avoid exposing the API surface to reconnaissance.
    docs_enabled: bool = True
    # Strict-Transport-Security header (only sent over HTTPS).
    hsts_enabled: bool = True
    # Comma-separated IPs / CIDRs allowed to set X-Forwarded-For. XFF from any
    # other peer is ignored, preventing client-side header spoofing.
    trusted_proxy_ips: str = ""
    # Allowed Host headers (TrustedHostMiddleware). Add your deployed hostname.
    trusted_hosts: str = "localhost,127.0.0.1,0.0.0.0,::1,testserver"

    # ─── Model ───────────────────────────────────────────────
    model_path: str = "models/phishing_model.joblib"
    feature_names_path: str = "models/feature_names.json"
    metadata_path: str = "models/model_metadata.json"
    # Seconds a cached prediction stays fresh before it is re-computed.
    cache_ttl_seconds: int = 300

    # ─── Deterministic overrides (post-model domain rules) ───
    # Trusted apex domain (whitelisted) → cap phishing probability at this value.
    whitelist_confidence_cap: float = 0.05
    # Brand-spoofing attempt → floor phishing probability at this value.
    brand_spoof_confidence_floor: float = 0.95

    # ─── Prediction thresholds ───────────────────────────────
    # Decision threshold: phishing probability at/above this is "PHISHING".
    decision_threshold: float = 0.5
    # Risk-level cutoffs: >= high_risk_threshold → HIGH; >= low_risk_threshold
    # → MEDIUM; below → LOW. Kept below the decision threshold by default so a
    # borderline "LEGITIMATE" verdict can still carry a MEDIUM risk signal.
    high_risk_threshold: float = 0.70
    low_risk_threshold: float = 0.40

    # ─── Logging ─────────────────────────────────────────────
    log_level: str = "INFO"
    # "text" (human-readable) or "json" (structured, one object per line).
    log_format: str = "text"

    @property
    def cors_origin_list(self) -> list[str]:
        """CORS origins as a parsed list (comma-separated env value)."""
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def trusted_proxy_ip_list(self) -> list[str]:
        """Trusted proxy IPs / CIDRs as a parsed list (comma-separated env value)."""
        return [o.strip() for o in self.trusted_proxy_ips.split(",") if o.strip()]

    @property
    def trusted_host_list(self) -> list[str]:
        """Allowed Host headers as a parsed list (comma-separated env value)."""
        return [h.strip() for h in self.trusted_hosts.split(",") if h.strip()]

    def is_trusted_proxy(self, peer_ip: str | None) -> bool:
        """
        Return True if `peer_ip` is one of the configured trusted proxies.

        An empty `trusted_proxy_ips` means no proxies are trusted, so the
        `X-Forwarded-For` header must not be honored.
        """
        if not peer_ip:
            return False
        try:
            addr = ip_address(peer_ip)
        except ValueError:
            return False
        for entry in self.trusted_proxy_ip_list:
            try:
                if addr in ip_network(entry, strict=False):
                    return True
            except ValueError:
                continue
        return False


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance (loaded once per process)."""
    return Settings()


settings = get_settings()
