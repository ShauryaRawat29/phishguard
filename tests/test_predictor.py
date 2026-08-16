"""
test_predictor.py
=================
Unit tests for the PhishGuardPredictor service.

The heavy real model / SHAP explainer is replaced by a stub via
monkeypatching `_load`, so these tests are fast and deterministic.
Run with: pytest tests/test_predictor.py -v
"""

import numpy as np
import pytest

from backend.services.predictor import PhishGuardPredictor, _get_risk_level
from ml.feature_extractor import FeatureExtractor


class StubModel:
    """Minimal stand-in exposing predict_proba() with a fixed phishing proba."""

    def __init__(self, phishing_proba: float) -> None:
        self._proba = phishing_proba
        self.calls = 0

    def predict_proba(self, X) -> np.ndarray:
        self.calls += 1
        return np.array([[1.0 - self._proba, self._proba]])


def _install_stub(monkeypatch, phishing_proba: float, is_loaded: bool = True) -> StubModel:
    """Patch _load so PhishGuardPredictor uses a fast stub instead of the model."""
    model = StubModel(phishing_proba)

    def fake_load(self, model_path, feature_names_path) -> None:
        self._model = model
        self._explainer = None
        self.feature_names = FeatureExtractor.FEATURE_NAMES
        self.is_loaded = is_loaded

    monkeypatch.setattr(PhishGuardPredictor, "_load", fake_load)
    return model


@pytest.fixture
def predictor(monkeypatch):
    _install_stub(monkeypatch, phishing_proba=0.99)
    return PhishGuardPredictor()


# ─── Prediction shape ────────────────────────────────────────────────────────


def test_predict_returns_full_schema(predictor):
    result = predictor.predict("https://example.com/login")
    for key in (
        "url",
        "prediction",
        "risk_level",
        "confidence",
        "features",
        "explanation",
        "timestamp",
    ):
        assert key in result, f"Missing key: {key}"
    assert result["prediction"] in {"PHISHING", "LEGITIMATE"}
    assert 0.0 <= result["confidence"] <= 1.0
    assert result["features"] != {}


def test_predict_high_proba_is_phishing(predictor):
    result = predictor.predict("https://example.com/login")
    assert result["prediction"] == "PHISHING"
    assert result["risk_level"] == "HIGH"


# ─── Whitelist override (cap) ────────────────────────────────────────────────


def test_whitelist_domain_caps_confidence(monkeypatch):
    model = _install_stub(monkeypatch, phishing_proba=0.60)
    p = PhishGuardPredictor()
    result = p.predict("https://github.com/user/repo")
    # is_whitelisted_domain=1 and not brand-spoofed -> cap to settings value (0.05)
    assert result["confidence"] <= 0.05
    assert result["prediction"] == "LEGITIMATE"
    assert model.calls == 1


# ─── Brand spoof override (floor) ────────────────────────────────────────────


def test_brand_spoof_floors_confidence(monkeypatch):
    model = _install_stub(monkeypatch, phishing_proba=0.10)
    p = PhishGuardPredictor()
    result = p.predict("http://paypa1-secure-login.xyz/account/verify?token=abc123")
    # is_brand_spoofed=1 (fuzzy digit typo) -> floor to settings value (0.95)
    assert result["confidence"] >= 0.95
    assert result["prediction"] == "PHISHING"
    assert model.calls == 1


# ─── Caching ─────────────────────────────────────────────────────────────────


def test_repeated_url_served_from_cache(monkeypatch):
    model = _install_stub(monkeypatch, phishing_proba=0.95)
    p = PhishGuardPredictor()
    first = p.predict("https://example.com/x")
    second = p.predict("https://example.com/x")
    assert first["confidence"] == second["confidence"]
    assert model.calls == 1  # inference ran only once

    # Different URL forces another inference.
    p.predict("https://example.com/y")
    assert model.calls == 2


def test_cache_is_capped(monkeypatch):
    _install_stub(monkeypatch, phishing_proba=0.5)
    p = PhishGuardPredictor()
    for i in range(600):  # > _CACHE_MAX_SIZE (512)
        p.predict(f"https://example.com/{i}")
    assert len(p._cache) <= 512


# ─── Model not loaded ────────────────────────────────────────────────────────


def test_predict_raises_when_model_missing(monkeypatch):
    _install_stub(monkeypatch, phishing_proba=0.5, is_loaded=False)
    p = PhishGuardPredictor()
    with pytest.raises(RuntimeError):
        p.predict("https://example.com")


# ─── Risk level mapping ──────────────────────────────────────────────────────


def test_risk_level_thresholds():
    assert _get_risk_level(0.95) == "HIGH"
    assert _get_risk_level(0.70) == "HIGH"
    assert _get_risk_level(0.40) == "MEDIUM"
    assert _get_risk_level(0.10) == "LOW"
