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


def test_cache_entries_expire_after_ttl(monkeypatch):
    """Entries older than `cache_ttl_seconds` are evicted and re-computed."""
    import backend.services.predictor as predictor_mod
    from backend import config

    model = _install_stub(monkeypatch, phishing_proba=0.9)
    p = PhishGuardPredictor()

    now = [1000.0]
    monkeypatch.setattr(predictor_mod.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(config.settings, "cache_ttl_seconds", 300)

    p.predict("https://example.com/ttl")
    assert model.calls == 1

    now[0] = 1299.0  # within TTL -> served from cache
    p.predict("https://example.com/ttl")
    assert model.calls == 1

    now[0] = 1301.0  # past TTL -> re-inference
    p.predict("https://example.com/ttl")
    assert model.calls == 2

    # The internal timestamp key never leaks into results.
    result = p.predict("https://example.com/ttl")
    assert "_cached_at" not in result


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


def test_risk_level_uses_configured_thresholds(monkeypatch):
    from backend import config

    monkeypatch.setattr(config.settings, "high_risk_threshold", 0.9)
    monkeypatch.setattr(config.settings, "low_risk_threshold", 0.3)
    assert _get_risk_level(0.85) == "MEDIUM"
    assert _get_risk_level(0.95) == "HIGH"


# ─── Decision threshold ──────────────────────────────────────────────────────


def test_decision_threshold_is_configurable(monkeypatch):
    """A configurable decision threshold flips the verdict for borderline scores."""
    from backend import config

    _install_stub(monkeypatch, phishing_proba=0.5)
    p = PhishGuardPredictor()

    monkeypatch.setattr(config.settings, "decision_threshold", 0.5)
    assert p.predict("https://example.com/threshold")["prediction"] == "PHISHING"

    monkeypatch.setattr(config.settings, "decision_threshold", 0.9)
    assert p.predict("https://example.com/threshold2")["prediction"] == "LEGITIMATE"


def test_borderline_legit_can_still_be_medium_risk(monkeypatch):
    """Below the decision threshold but above low_risk_threshold -> MEDIUM."""
    from backend import config

    _install_stub(monkeypatch, phishing_proba=0.45)
    p = PhishGuardPredictor()

    monkeypatch.setattr(config.settings, "decision_threshold", 0.5)
    result = p.predict("https://example.com/borderline")
    assert result["prediction"] == "LEGITIMATE"
    assert result["risk_level"] == "MEDIUM"


# ─── Model load failure paths ────────────────────────────────────────────────


def test_load_missing_model_file(monkeypatch, tmp_path):
    from backend import config

    monkeypatch.setattr(config.settings, "model_path", str(tmp_path / "missing.joblib"))
    monkeypatch.setattr(config.settings, "feature_names_path", str(tmp_path / "none.json"))
    assert PhishGuardPredictor().is_loaded is False


def test_load_rejects_non_estimator(monkeypatch, tmp_path):
    import joblib

    from backend import config

    model_path = tmp_path / "model.joblib"
    joblib.dump({"not": "an estimator"}, model_path)
    monkeypatch.setattr(config.settings, "model_path", str(model_path))
    monkeypatch.setattr(config.settings, "feature_names_path", str(tmp_path / "none.json"))
    assert PhishGuardPredictor().is_loaded is False


def test_load_rejects_feature_name_mismatch(monkeypatch, tmp_path):
    import json

    import joblib

    from backend import config

    model_path = tmp_path / "model.joblib"
    joblib.dump(StubModel(0.5), model_path)
    feature_names_path = tmp_path / "feature_names.json"
    feature_names_path.write_text(json.dumps(["wrong", "names"]))
    monkeypatch.setattr(config.settings, "model_path", str(model_path))
    monkeypatch.setattr(config.settings, "feature_names_path", str(feature_names_path))
    assert PhishGuardPredictor().is_loaded is False


# ─── Probability calibration ─────────────────────────────────────────────────


def test_predict_applies_calibrator(monkeypatch, tmp_path):
    """A fitted isotonic calibrator transforms the raw phishing probability."""
    import joblib
    from sklearn.isotonic import IsotonicRegression

    from backend import config

    model = _install_stub(monkeypatch, phishing_proba=0.99)
    p = PhishGuardPredictor()

    iso = IsotonicRegression(out_of_bounds="clip")
    iso.fit([0.0, 0.5, 1.0], [0.0, 0.4, 0.75])
    cal_path = tmp_path / "calibrator.joblib"
    joblib.dump(iso, cal_path)

    monkeypatch.setattr(config.settings, "calibrator_path", str(cal_path))
    p._calibrator = p._load_calibrator(str(cal_path))

    result = p.predict("https://example.com/calibrated")
    assert result["confidence"] == pytest.approx(0.74, abs=0.01)
    assert model.calls == 1


def test_predict_falls_back_to_raw_without_calibrator(monkeypatch):
    """No calibrator loaded -> raw model probability is reported unchanged."""
    _install_stub(monkeypatch, phishing_proba=0.99)
    p = PhishGuardPredictor()
    assert p._calibrator is None
    result = p.predict("https://example.com/no-calibrator")
    assert result["confidence"] == pytest.approx(0.99, abs=1e-4)


def test_load_calibrator_missing_file_returns_none(monkeypatch, tmp_path):
    _install_stub(monkeypatch, phishing_proba=0.5)
    p = PhishGuardPredictor()
    assert p._load_calibrator(str(tmp_path / "missing.joblib")) is None


def test_load_calibrator_rejects_non_predictable_object(monkeypatch, tmp_path):
    import joblib

    _install_stub(monkeypatch, phishing_proba=0.5)
    p = PhishGuardPredictor()
    bad = tmp_path / "bad.joblib"
    joblib.dump({"not": "a calibrator"}, bad)
    assert p._load_calibrator(str(bad)) is None


# ─── Cache helpers ───────────────────────────────────────────────────────────


def test_clear_cache(monkeypatch):
    _install_stub(monkeypatch, phishing_proba=0.5)
    p = PhishGuardPredictor()
    p.predict("https://example.com/clear")
    assert p._cache != {}
    p.clear_cache()
    assert p._cache == {}


def test_predict_survives_shap_failure(monkeypatch):
    """If the SHAP explainer fails, the prediction still succeeds (empty explanation)."""
    _install_stub(monkeypatch, phishing_proba=0.9)
    p = PhishGuardPredictor()

    class BadExplainer:
        def explain(self, feature_vector, top_n=5):
            raise Exception("shap boom")

    p._explainer = BadExplainer()
    result = p.predict("https://example.com/explain-fail")
    assert result["prediction"] == "PHISHING"
    assert result["explanation"] == []
