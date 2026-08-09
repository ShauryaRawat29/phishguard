"""
predictor.py
============
Wraps the trained ML model and SHAP explainer into a single prediction service.

The model is loaded once at application startup and reused for every request.
This avoids the significant overhead of loading a scikit-learn / XGBoost model
on every prediction request.

Usage (called from routes):
    from backend.services.predictor import PhishGuardPredictor
    predictor = PhishGuardPredictor()
    result = predictor.predict("https://example.com")
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

import joblib
import numpy as np

from ml.explainer import PhishGuardExplainer
from ml.feature_extractor import FeatureExtractor

# ─── Default model paths (overridden by env vars) ────────────────────────────
_DEFAULT_MODEL_PATH = os.path.join("models", "phishing_model.joblib")
_DEFAULT_FEATURE_NAMES_PATH = os.path.join("models", "feature_names.json")


def _get_risk_level(confidence: float) -> str:
    """
    Map a phishing probability score to a categorical risk level.

    Thresholds:
        >= 0.70 → HIGH
        >= 0.40 → MEDIUM
        <  0.40 → LOW

    Args:
        confidence: Phishing probability from the model (0.0 to 1.0).

    Returns:
        "HIGH", "MEDIUM", or "LOW".
    """
    if confidence >= 0.70:
        return "HIGH"
    elif confidence >= 0.40:
        return "MEDIUM"
    else:
        return "LOW"


class PhishGuardPredictor:
    """
    Orchestrates feature extraction, model inference, and SHAP explanation.

    This class is instantiated once at application startup and held in the
    FastAPI app's state. It is thread-safe for read-only inference.

    Attributes:
        is_loaded:    True if the model was successfully loaded.
        feature_names: The ordered list of feature names expected by the model.
    """

    def __init__(
        self,
        model_path: str | None = None,
        feature_names_path: str | None = None,
    ) -> None:
        """
        Load the trained model and initialize the feature extractor and explainer.

        Args:
            model_path:          Path to the joblib model file.
            feature_names_path:  Path to the feature_names.json file.
        """
        self.is_loaded: bool = False
        self._model: Any = None
        self._explainer: PhishGuardExplainer | None = None
        self._extractor: FeatureExtractor = FeatureExtractor()
        self.feature_names: list[str] = FeatureExtractor.FEATURE_NAMES

        model_path = model_path or os.getenv("MODEL_PATH", _DEFAULT_MODEL_PATH)
        feature_names_path = feature_names_path or os.getenv(
            "FEATURE_NAMES_PATH", _DEFAULT_FEATURE_NAMES_PATH
        )

        self._load(model_path, feature_names_path)

    def _load(self, model_path: str, feature_names_path: str) -> None:
        """Load the model and set up the SHAP explainer."""
        try:
            self._model = joblib.load(model_path)

            # Load feature names from JSON if available (for consistency check)
            if os.path.exists(feature_names_path):
                with open(feature_names_path) as f:
                    saved_names = json.load(f)
                if saved_names != self.feature_names:
                    raise ValueError(
                        "Feature names in feature_names.json do not match "
                        "FeatureExtractor.FEATURE_NAMES. Retrain the model."
                    )

            self._explainer = PhishGuardExplainer(self._model, self.feature_names)
            self.is_loaded = True
            print(f"[PhishGuard] Model loaded from: {model_path}")
        except FileNotFoundError:
            print(
                f"[PhishGuard] WARNING: Model file not found at '{model_path}'. "
                "Run the training notebook first, then restart the server."
            )
        except Exception as e:
            print(f"[PhishGuard] ERROR loading model: {e}")

    def predict(self, url: str) -> dict:
        """
        Analyze a URL and return a full prediction result.

        Args:
            url: A validated URL string.

        Returns:
            A dict matching the AnalyzeResponse schema.

        Raises:
            RuntimeError: If the model is not loaded.
        """
        if not self.is_loaded:
            raise RuntimeError(
                "The ML model is not loaded. "
                "Train the model first and restart the server."
            )

        # 1. Extract features
        feature_dict = self._extractor.extract(url)
        feature_vector = [feature_dict[name] for name in self.feature_names]

        # 2. Run inference
        X = np.array(feature_vector).reshape(1, -1)
        proba = self._model.predict_proba(X)[0]

        # Class 1 = phishing probability
        phishing_proba = float(proba[1])

        # Domain reputation overrides for extreme deterministic signals
        if feature_dict.get("is_whitelisted_domain") == 1 and feature_dict.get("is_brand_spoofed") == 0:
            # Trusted apex domain (e.g. google.com, paypal.com, github.com)
            phishing_proba = min(phishing_proba, 0.05)
        elif feature_dict.get("is_brand_spoofed") == 1:
            # Brand spoofing attempt (e.g. paypal.ab, paypal-security.xyz)
            phishing_proba = max(phishing_proba, 0.95)

        prediction = "PHISHING" if phishing_proba >= 0.5 else "LEGITIMATE"
        risk_level = _get_risk_level(phishing_proba)

        # 3. Generate SHAP explanation
        explanation = []
        if self._explainer:
            try:
                explanation = self._explainer.explain(feature_vector, top_n=5)
            except Exception as e:
                print(f"[PhishGuard] SHAP explanation failed: {e}")

        return {
            "url": url,
            "prediction": prediction,
            "risk_level": risk_level,
            "confidence": round(phishing_proba, 4),
            "features": {k: round(float(v), 4) for k, v in feature_dict.items()},
            "explanation": explanation,
            "timestamp": datetime.now(timezone.utc),
        }
