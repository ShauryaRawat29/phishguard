"""
test_config.py
==============
Unit tests for backend configuration, specifically the trusted-proxy logic.
Run with: pytest tests/test_config.py -v
"""

from backend.config import settings


def test_is_trusted_proxy_false_when_no_peer():
    assert settings.is_trusted_proxy(None) is False


def test_is_trusted_proxy_false_on_invalid_ip(monkeypatch):
    monkeypatch.setattr(settings, "trusted_proxy_ips", "192.0.2.10")
    assert settings.is_trusted_proxy("not-an-ip") is False


def test_is_trusted_proxy_skips_invalid_entries(monkeypatch):
    # First entry is garbage, second matches the peer -> returns True.
    monkeypatch.setattr(settings, "trusted_proxy_ips", "garbage, 192.0.2.10")
    assert settings.is_trusted_proxy("192.0.2.10") is True


def test_is_trusted_proxy_false_when_nothing_matches(monkeypatch):
    monkeypatch.setattr(settings, "trusted_proxy_ips", "192.0.2.10")
    assert settings.is_trusted_proxy("203.0.113.5") is False


def test_is_trusted_proxy_matches_cidr(monkeypatch):
    monkeypatch.setattr(settings, "trusted_proxy_ips", "10.0.0.0/8")
    assert settings.is_trusted_proxy("10.1.2.3") is True


# ─── Prediction thresholds ───────────────────────────────────────────────────


def test_threshold_defaults():
    assert settings.decision_threshold == 0.5
    assert settings.high_risk_threshold == 0.70
    assert settings.low_risk_threshold == 0.40


def test_thresholds_read_from_env(monkeypatch):
    monkeypatch.setenv("DECISION_THRESHOLD", "0.6")
    monkeypatch.setenv("HIGH_RISK_THRESHOLD", "0.8")
    monkeypatch.setenv("LOW_RISK_THRESHOLD", "0.2")

    from backend.config import get_settings

    fresh = get_settings()
    # (get_settings is lru_cached; force a reload by clearing the cache)
    get_settings.cache_clear()
    fresh = get_settings()
    try:
        assert fresh.decision_threshold == 0.6
        assert fresh.high_risk_threshold == 0.8
        assert fresh.low_risk_threshold == 0.2
    finally:
        get_settings.cache_clear()
