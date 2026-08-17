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
