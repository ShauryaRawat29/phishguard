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

    # ─── Model ───────────────────────────────────────────────
    model_path: str = "models/phishing_model.joblib"
    feature_names_path: str = "models/feature_names.json"
    metadata_path: str = "models/model_metadata.json"

    # ─── Deterministic overrides (post-model domain rules) ───
    # Trusted apex domain (whitelisted) → cap phishing probability at this value.
    whitelist_confidence_cap: float = 0.05
    # Brand-spoofing attempt → floor phishing probability at this value.
    brand_spoof_confidence_floor: float = 0.95

    # ─── Logging ─────────────────────────────────────────────
    log_level: str = "INFO"

    @property
    def cors_origin_list(self) -> list[str]:
        """CORS origins as a parsed list (comma-separated env value)."""
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance (loaded once per process)."""
    return Settings()


settings = get_settings()
