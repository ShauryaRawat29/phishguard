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
    assert body["feature_count"] == 33
    assert body["uptime_seconds"] >= 0
    assert isinstance(body["model_metadata"], dict)
    assert body["model_metadata"]["model_type"] == "XGBoost"


def test_health_degraded_when_model_missing(monkeypatch):
    STATE["model_loaded"] = False
    monkeypatch.setattr(PhishGuardPredictor, "_load", _stub_load)
    from backend.main import app

    with TestClient(app) as c:
        resp = c.get("/api/health")
    STATE["model_loaded"] = True
    assert resp.status_code == 200
    assert resp.json()["status"] == "degraded"


# ─── Request-ID middleware ──────────────────────────────────────────────────


def test_response_carries_generated_request_id(client):
    resp = client.get("/api/health")
    assert "X-Request-ID" in resp.headers
    assert resp.headers["X-Request-ID"]


def test_response_reflects_incoming_request_id(client):
    resp = client.get("/api/health", headers={"X-Request-ID": "trace-123"})
    assert resp.headers["X-Request-ID"] == "trace-123"


def test_request_id_middleware_survives_errors(client):
    from backend.main import app

    class BoomPredictor:
        is_loaded = True

        def predict(self, url):
            raise Exception("boom")

    app.state.predictor = BoomPredictor()
    resp = client.post("/api/analyze", json={"url": "https://example.com"})
    assert resp.status_code == 500
    assert "X-Request-ID" in resp.headers


def test_request_id_middleware_handles_unhandled_exceptions():
    """An unhandled exception is logged with the request id and re-raised."""
    import asyncio

    import pytest
    from starlette.datastructures import Address, Headers
    from starlette.requests import Request

    from backend.main import request_id_and_access_log

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/boom",
        "raw_path": b"/boom",
        "scheme": "http",
        "server": ("testserver", 80),
        "client": Address("1.2.3.4", 1234),
        "headers": Headers({}).raw,
        "query_string": b"",
        "state": {},
        "root_path": "",
    }
    request = Request(scope)

    async def boom_call_next(request):
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        asyncio.run(request_id_and_access_log(request, boom_call_next))


# ─── Model metadata loading ────────────────────────────────────────────────


def test_load_model_metadata_missing_file_returns_none(monkeypatch, tmp_path):
    from backend import config
    from backend.main import _load_model_metadata

    monkeypatch.setattr(config.settings, "metadata_path", str(tmp_path / "missing.json"))
    assert _load_model_metadata() is None


def test_load_model_metadata_unreadable_returns_none(monkeypatch, tmp_path):
    import backend.main as main_mod
    from backend import config

    bad = tmp_path / "metadata.json"
    bad.write_text("{not valid json")
    monkeypatch.setattr(config.settings, "metadata_path", str(bad))
    assert main_mod._load_model_metadata() is None


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


def test_extended_security_headers_present(client):
    resp = client.get("/api/health")
    assert "Content-Security-Policy" in resp.headers
    assert "Cross-Origin-Resource-Policy" in resp.headers
    assert resp.headers["Cross-Origin-Resource-Policy"] == "same-origin"
    assert resp.headers["Cache-Control"] == "no-store"


def test_hsts_emitted_when_secure_proxy(monkeypatch, client):
    from backend.config import settings

    monkeypatch.setattr(settings, "hsts_enabled", True)
    monkeypatch.setattr(settings, "trust_proxy_headers", True)

    resp = client.get("/api/health", headers={"X-Forwarded-Proto": "https"})
    assert resp.headers["Strict-Transport-Security"] == "max-age=31536000; includeSubDomains"


def test_hsts_omitted_over_plain_http(monkeypatch, client):
    from backend.config import settings

    monkeypatch.setattr(settings, "hsts_enabled", True)

    resp = client.get("/api/health")
    assert "Strict-Transport-Security" not in resp.headers


def test_trusted_host_rejects_unknown_host(client):
    resp = client.get("/api/health", headers={"Host": "evil.example.com"})
    assert resp.status_code == 400


def test_docs_disabled_when_configured_off(monkeypatch):
    import importlib

    from backend.config import settings

    monkeypatch.setattr(settings, "docs_enabled", False)
    import backend.main as main

    importlib.reload(main)
    app = main.app
    with TestClient(app) as c:
        assert c.get("/docs").status_code == 404
        assert c.get("/openapi.json").status_code == 404

    monkeypatch.setattr(settings, "docs_enabled", True)
    importlib.reload(main)


def test_docs_available_by_default(client):
    resp = client.get("/docs")
    assert resp.status_code == 200


# ─── Static frontend mount ───────────────────────────────────────────────────


def test_frontend_served_at_root(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "PhishGuard" in resp.text


# ─── GET /api/features ───────────────────────────────────────────────────────


def test_features_lists_names_and_labels(client):
    resp = client.get("/api/features")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["feature_names"]) == 33
    assert set(body["feature_names"]) == set(body["feature_labels"])
    assert body["feature_labels"]["url_length"] == "URL length"
    assert body["feature_labels"]["has_punycode"] == "Internationalized (punycode) domain"


# ─── Rate-limit key helpers ──────────────────────────────────────────────────


def test_client_key_without_proxy_header():
    from backend.rate_limit import _client_key

    class FakeRequest:
        class client:
            host = "1.2.3.4"

        headers = {}

    assert _client_key(FakeRequest()) == "1.2.3.4"


def test_client_key_honors_proxy_header_when_peer_trusted(monkeypatch):
    from backend import rate_limit
    from backend.config import settings

    monkeypatch.setattr(settings, "trust_proxy_headers", True)
    monkeypatch.setattr(settings, "trusted_proxy_ips", "1.2.3.4, 10.0.0.0/8")

    class FakeRequest:
        class client:
            host = "1.2.3.4"

        headers = {"X-Forwarded-For": "9.9.9.9, 1.2.3.4"}

    assert rate_limit._client_key(FakeRequest()) == "9.9.9.9"


def test_client_key_ignores_proxy_header_when_peer_untrusted(monkeypatch):
    from backend import rate_limit
    from backend.config import settings

    monkeypatch.setattr(settings, "trust_proxy_headers", True)
    monkeypatch.setattr(settings, "trusted_proxy_ips", "192.0.2.10")

    class FakeRequest:
        class client:
            host = "1.2.3.4"

        headers = {"X-Forwarded-For": "9.9.9.9, 1.2.3.4"}

    assert rate_limit._client_key(FakeRequest()) == "1.2.3.4"


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


# ─── Rate-limit key edge case ────────────────────────────────────────────────


def test_client_key_unknown_when_no_client():
    from backend.rate_limit import _client_key

    class FakeRequest:
        client = None
        headers = {}

    assert _client_key(FakeRequest()) == "unknown"


# ─── Analyzer error paths ────────────────────────────────────────────────────


def test_analyze_prediction_failure_returns_500(client):
    from backend.main import app

    class BoomPredictor:
        is_loaded = True

        def predict(self, url):
            raise Exception("boom")

    app.state.predictor = BoomPredictor()
    resp = client.post("/api/analyze", json={"url": "https://example.com"})
    assert resp.status_code == 500
    assert resp.json()["detail"]["error"] == "PREDICTION_FAILED"


def test_validator_handles_urlparse_failure(monkeypatch):
    import backend.services.validator as validator
    from backend.services.validator import URLValidationError, validate_url

    def boom(url):
        raise ValueError("unparseable")

    monkeypatch.setattr(validator, "urlparse", boom)
    with pytest.raises(URLValidationError) as exc:
        validate_url("https://example.com")
    assert exc.value.code == "INVALID_URL"


# ─── CORS wildcard rejected in production ────────────────────────────────────


def test_cors_wildcard_ignored_in_production(monkeypatch):
    import importlib

    from backend.config import settings

    monkeypatch.setattr(settings, "app_env", "production")
    monkeypatch.setattr(settings, "cors_origins", "*")
    import backend.main as main

    importlib.reload(main)
    app = main.app
    with TestClient(app) as c:
        resp = c.options(
            "/api/health",
            headers={
                "Origin": "https://evil.example.com",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert "Access-Control-Allow-Origin" not in resp.headers

    monkeypatch.setattr(settings, "app_env", "development")
    monkeypatch.setattr(settings, "cors_origins", "*")
    importlib.reload(main)
