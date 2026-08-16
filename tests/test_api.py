"""
test_api.py
===========
Integration tests for the FastAPI application.

The real model / SHAP explainer are stubbed out via monkeypatching
`PhishGuardPredictor._load`, so the full app (lifespan, middleware, routes,
static mount) is exercised quickly without loading the trained model.
Run with: pytest tests/test_api.py -v
"""

import numpy as np
import pytest
from fastapi.testclient import TestClient

from backend.services.predictor import PhishGuardPredictor
from ml.feature_extractor import FeatureExtractor

STATE = {"model_loaded": True}


class StubModel:
    """Fixed-probability stand-in for the real classifier."""

    def predict_proba(self, X) -> np.ndarray:
        return np.array([[0.05, 0.95]])


def _stub_load(self, model_path, feature_names_path) -> None:
    self._model = StubModel()
    self._explainer = None
    self.feature_names = FeatureExtractor.FEATURE_NAMES
    self.is_loaded = STATE["model_loaded"]


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(PhishGuardPredictor, "_load", _stub_load)
    from backend.main import app

    with TestClient(app) as c:
        yield c


# ─── Health ──────────────────────────────────────────────────────────────────


def test_health_ok(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["model_loaded"] is True
    assert body["version"]


def test_health_degraded_when_model_missing(monkeypatch):
    STATE["model_loaded"] = False
    monkeypatch.setattr(PhishGuardPredictor, "_load", _stub_load)
    from backend.main import app

    with TestClient(app) as c:
        resp = c.get("/api/health")
    STATE["model_loaded"] = True
    assert resp.status_code == 200
    assert resp.json()["status"] == "degraded"


# ─── POST /api/analyze ───────────────────────────────────────────────────────


def test_analyze_valid_url(client):
    resp = client.post("/api/analyze", json={"url": "https://example.com/login"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["prediction"] in {"PHISHING", "LEGITIMATE"}
    assert body["risk_level"] in {"HIGH", "MEDIUM", "LOW"}
    assert 0.0 <= body["confidence"] <= 1.0
    assert "features" in body
    assert isinstance(body["explanation"], list)
    assert "timestamp" in body


def test_analyze_unsafe_scheme_rejected(client):
    resp = client.post("/api/analyze", json={"url": "file:///etc/passwd"})
    assert resp.status_code == 422
    assert resp.json()["detail"]["error"] == "INVALID_SCHEME"


def test_analyze_empty_url_rejected(client):
    resp = client.post("/api/analyze", json={"url": ""})
    assert resp.status_code == 422


def test_analyze_model_unavailable(client, monkeypatch):
    STATE["model_loaded"] = False
    monkeypatch.setattr(PhishGuardPredictor, "_load", _stub_load)
    from backend.main import app

    with TestClient(app) as c:
        resp = c.post("/api/analyze", json={"url": "https://example.com"})
    STATE["model_loaded"] = True
    assert resp.status_code == 503
    assert resp.json()["detail"]["error"] == "MODEL_UNAVAILABLE"


# ─── Security headers ────────────────────────────────────────────────────────


def test_security_headers_present(client):
    resp = client.get("/api/health")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Referrer-Policy"] == "no-referrer"
    assert "Cross-Origin-Opener-Policy" in resp.headers


# ─── Static frontend mount ───────────────────────────────────────────────────


def test_frontend_served_at_root(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "PhishGuard" in resp.text


# ─── Rate-limit key helpers ──────────────────────────────────────────────────


def test_client_key_without_proxy_header():
    from backend.rate_limit import _client_key

    class FakeRequest:
        class client:
            host = "1.2.3.4"

        headers = {}

    assert _client_key(FakeRequest()) == "1.2.3.4"


def test_client_key_honors_proxy_header_when_trusted(monkeypatch):
    from backend import rate_limit
    from backend.config import settings

    monkeypatch.setattr(settings, "trust_proxy_headers", True)

    class FakeRequest:
        class client:
            host = "1.2.3.4"

        headers = {"X-Forwarded-For": "9.9.9.9, 1.2.3.4"}

    assert rate_limit._client_key(FakeRequest()) == "9.9.9.9"


def test_analyze_limit_string_derived_from_settings():
    from backend.config import settings
    from backend.rate_limit import analyze_limit

    assert analyze_limit() == f"{settings.rate_limit_per_minute}/minute"


def test_rate_limit_exceeded_returns_429():
    """A low-limit endpoint must return 429 once the budget is exhausted."""
    from fastapi import FastAPI, Request
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.errors import RateLimitExceeded
    from slowapi.util import get_remote_address

    app = FastAPI()
    limiter = Limiter(key_func=get_remote_address)
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    @app.post("/limited")
    @limiter.limit("2/minute")
    def limited(request: Request):
        return {"ok": True}

    with TestClient(app) as c:
        assert c.post("/limited").status_code == 200
        assert c.post("/limited").status_code == 200
        assert c.post("/limited").status_code == 429
