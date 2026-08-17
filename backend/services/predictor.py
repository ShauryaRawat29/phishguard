"""
predictor.py
============
Wraps the trained ML model and SHAP explainer into a single prediction service.

The model is loaded once at application startup and reused for every request.
This avoids the significant overhead of loading a scikit-learn / XGBoost model
on every prediction request. Identical URL predictions are cached to avoid
re-running SHAP inference.

Usage (called from routes):
    from backend.services.predictor import PhishGuardPredictor
    predictor = PhishGuardPredictor()
    result = predictor.predict("https://example.com")
"""

from __future__ import annotations

import json
import os
import threading
import time
from datetime import UTC, datetime
from typing import Any

import joblib
import numpy as np

from backend.config import settings
from backend.logging import get_logger
from ml.explainer import PhishGuardExplainer
from ml.feature_extractor import FeatureExtractor

logger = get_logger(__name__)

# Maximum number of unique URLs to cache prediction results for.
_CACHE_MAX_SIZE = 512

# Model type expected by the pipeline (matches ml/train.py).
_EXPECTED_MODEL_TYPES = {"XGBClassifier", "RandomForestClassifier"}


def _get_risk_level(confidence: float) -> str:
    """
    Map a phishing probability score to a categorical risk level.

    Thresholds are configurable via Settings (`high_risk_threshold` /
    `low_risk_threshold`); defaults are HIGH >= 0.70, MEDIUM >= 0.40, else LOW.

    Args:
        confidence: Phishing probability from the model (0.0 to 1.0).

    Returns:
        "HIGH", "MEDIUM", or "LOW".
    """
    if confidence >= settings.high_risk_threshold:
        return "HIGH"
    elif confidence >= settings.low_risk_threshold:
        return "MEDIUM"
    else:
        return "LOW"


class PhishGuardPredictor:
    """
    Orchestrates feature extraction, model inference, and SHAP explanation.

    This class is instantiated once at application startup and held in the
    FastAPI app's state. Reads its configuration from `backend.config.settings`.

    Thread-safety: inference on the loaded model is read-only and safe for
    concurrent calls; access to the prediction cache is guarded by a lock.

    Attributes:
        is_loaded:    True if the model was successfully loaded.
        feature_names: The ordered list of feature names expected by the model.
    """

    def __init__(self) -> None:
        """Load the trained model and initialize the extractor and explainer."""
        self.is_loaded: bool = False
        self._model: Any = None
        self._explainer: PhishGuardExplainer | None = None
        self._extractor: FeatureExtractor = FeatureExtractor()
        self.feature_names: list[str] = FeatureExtractor.FEATURE_NAMES

        self._cache: dict[str, dict] = {}
        self._cache_lock = threading.Lock()

        self._load(settings.model_path, settings.feature_names_path)

    def _load(self, model_path: str, feature_names_path: str) -> None:
        """
        Load the model, validate it, and set up the SHAP explainer.

        Args:
            model_path:         Path to the joblib model file.
            feature_names_path: Path to the feature_names.json file.
        """
        try:
            self._model = joblib.load(model_path)

            # Validate the estimator exposes probability prediction.
            if not hasattr(self._model, "predict_proba"):
                raise ValueError(
                    "Loaded model does not implement predict_proba(); "
                    "expected a scikit-learn / XGBoost classifier."
                )

            # Ensure the saved feature schema matches the extractor.
            if feature_names_path and os.path.exists(feature_names_path):
                with open(feature_names_path) as f:
                    saved_names = json.load(f)
                if saved_names != self.feature_names:
                    raise ValueError(
                        "Feature names in feature_names.json do not match "
                        "FeatureExtractor.FEATURE_NAMES. Retrain the model."
                    )

            self._explainer = PhishGuardExplainer(self._model, self.feature_names)
            self.is_loaded = True
            logger.info("Model loaded from: %s", model_path)
        except FileNotFoundError:
            logger.warning(
                "Model file not found at '%s'. "
                "Run `python scripts/rebuild_model.py`, then restart the server.",
                model_path,
            )
        except Exception as e:
            logger.error("Failed to load model: %s", e)

    # ─── Prediction ────────────────────────────────────────────────────────────

    def predict(self, url: str) -> dict:
        """
        Analyze a URL and return a full prediction result.

        Identical URLs are served from an in-memory cache to avoid re-running
        feature extraction and SHAP inference.

        Args:
            url: A validated URL string.

        Returns:
            A dict matching the AnalyzeResponse schema.

        Raises:
            RuntimeError: If the model is not loaded.
        """
        if not self.is_loaded:
            raise RuntimeError(
                "The ML model is not loaded. Train the model first and restart the server."
            )

        cached = self._cache_get(url)
        if cached is not None:
            cached["timestamp"] = datetime.now(UTC)
            return cached

        # 1. Extract features
        feature_dict = self._extractor.extract(url)
        feature_vector = [feature_dict[name] for name in self.feature_names]

        # 2. Run inference
        X = np.array(feature_vector).reshape(1, -1)
        proba = self._model.predict_proba(X)[0]
        phishing_proba = float(proba[1])

        # 3. Deterministic domain-reputation overrides (configurable).
        if (
            feature_dict.get("is_whitelisted_domain") == 1
            and feature_dict.get("is_brand_spoofed") == 0
        ):
            # Trusted apex domain (e.g. google.com, paypal.com, github.com)
            phishing_proba = min(phishing_proba, settings.whitelist_confidence_cap)
        elif feature_dict.get("is_brand_spoofed") == 1:
            # Brand spoofing attempt (e.g. paypal.ab, paypal-security.xyz)
            phishing_proba = max(phishing_proba, settings.brand_spoof_confidence_floor)

        prediction = "PHISHING" if phishing_proba >= settings.decision_threshold else "LEGITIMATE"
        risk_level = _get_risk_level(phishing_proba)

        # 4. Generate SHAP explanation
        explanation: list[dict] = []
        if self._explainer:
            try:
                explanation = self._explainer.explain(feature_vector, top_n=5)
            except Exception as e:
                logger.exception("SHAP explanation failed: %s", e)

        result = {
            "url": url,
            "prediction": prediction,
            "risk_level": risk_level,
            "confidence": round(phishing_proba, 4),
            "features": {k: round(float(v), 4) for k, v in feature_dict.items()},
            "explanation": explanation,
            "timestamp": datetime.now(UTC),
        }

        self._cache_put(url, result)
        return result

    # ─── Cache helpers ─────────────────────────────────────────────────────────

    def _cache_get(self, url: str) -> dict | None:
        """Return a cached result dict for url (without mutating callers)."""
        with self._cache_lock:
            cached = self._cache.get(url)
            if cached is None:
                return None
            # Expire stale entries after `cache_ttl_seconds` (configurable via
            # Settings) so predictions don't go stale forever.
            age = time.monotonic() - cached.get("_cached_at", 0)
            if age > settings.cache_ttl_seconds:
                self._cache.pop(url, None)
                return None
            entry = dict(cached)
            entry.pop("_cached_at", None)
            return entry

    def _cache_put(self, url: str, result: dict) -> None:
        """Store a result, evicting the oldest entry when the cache is full."""
        with self._cache_lock:
            if len(self._cache) >= _CACHE_MAX_SIZE:
                # FIFO eviction: drop the oldest inserted key.
                self._cache.pop(next(iter(self._cache)), None)
            entry = dict(result)
            entry["_cached_at"] = time.monotonic()
            self._cache[url] = entry

    def clear_cache(self) -> None:
        """Drop all cached predictions (used in tests / on demand)."""
        with self._cache_lock:
            self._cache.clear()
