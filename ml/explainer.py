"""
explainer.py
============
SHAP-based explainability for PhishGuard predictions.

Wraps SHAP's TreeExplainer to produce per-prediction feature contributions.
These are the actual model explanations — not hard-coded rules.

Usage:
    from ml.explainer import PhishGuardExplainer

    explainer = PhishGuardExplainer(model, feature_names)
    explanation = explainer.explain(feature_vector, top_n=5)
"""

from __future__ import annotations

import numpy as np

# Human-readable labels for each feature name
FEATURE_LABELS: dict[str, str] = {
    "url_length": "URL length",
    "domain_length": "Domain length",
    "path_length": "Path length",
    "num_dots": "Number of dots (.)",
    "num_hyphens": "Number of hyphens (-)",
    "num_underscores": "Number of underscores (_)",
    "num_slashes": "Number of slashes (/)",
    "num_question_marks": "Number of question marks (?)",
    "num_at_symbols": "Contains @ symbol",
    "num_digits": "Number of digits",
    "digit_ratio": "Digit ratio in URL",
    "has_ip_address": "Domain is an IP address",
    "uses_https": "Uses HTTPS",
    "has_port": "Non-standard port in URL",
    "subdomain_count": "Number of subdomains",
    "has_suspicious_tld": "Suspicious top-level domain",
    "suspicious_keyword_count": "Suspicious keywords in URL",
    "has_encoded_chars": "Percent-encoded characters",
    "double_slash_in_path": "Double slash in path",
    "has_hex_encoding": "Hex encoding detected",
    "shortening_service": "URL shortening service used",
    "url_entropy": "URL randomness (entropy)",
    "domain_hyphen_count": "Hyphens in domain name",
    "path_token_count": "Number of path segments",
    "num_special_chars": "Special characters in URL",
    "is_brand_spoofed": "Spoofed brand name detected in domain",
    "is_whitelisted_domain": "Known trusted legitimate domain",
}


class PhishGuardExplainer:
    """
    Computes SHAP-based per-prediction explanations for the PhishGuard model.

    Uses SHAP's TreeExplainer, which is exact (no approximation) for tree-based
    models like XGBoost and Random Forest. Very fast for single-sample inference.

    Attributes:
        _shap_explainer: The fitted SHAP TreeExplainer instance.
        feature_names:   Ordered list of feature names matching model input.
    """

    def __init__(self, model, feature_names: list[str]) -> None:
        """
        Initialize and fit the SHAP explainer.

        Args:
            model:         The trained scikit-learn / XGBoost model object.
            feature_names: Ordered list of feature names used during training.
        """
        try:
            import shap

            self._shap_explainer = shap.TreeExplainer(model)
        except Exception as e:
            raise RuntimeError(
                f"Failed to initialize SHAP TreeExplainer: {e}. "
                "Ensure the model is a tree-based estimator (XGBoost, RandomForest, etc.)."
            ) from e

        self.feature_names = feature_names

    def explain(
        self,
        feature_vector: list[int | float],
        top_n: int = 5,
    ) -> list[dict]:
        """
        Generate a human-readable explanation for a single prediction.

        Args:
            feature_vector: Ordered list of feature values (same order as feature_names).
            top_n:          Number of top contributing features to return.

        Returns:
            A list of dicts, sorted by absolute SHAP value descending.
            Each dict has:
                - feature:   internal feature name
                - label:     human-readable label
                - value:     the raw feature value for this URL
                - shap_value: the SHAP contribution (float)
                - direction: "phishing" if positive contribution, "legitimate" if negative
                - impact:    "high" | "medium" | "low" based on relative magnitude
        """

        X = np.array(feature_vector).reshape(1, -1)
        shap_values = self._shap_explainer.shap_values(X)

        # TreeExplainer output shapes vary by model / SHAP version:
        #   - XGBoost binary classifier -> list [class0, class1]
        #   - sklearn tree              -> ndarray (1, n_features, 2)
        #   - single-output tree        -> ndarray (1, n_features)
        # We always want the positive (phishing) class contributions.
        if isinstance(shap_values, list):
            contributions = np.asarray(shap_values[1])[0]
        else:
            values = np.asarray(shap_values)
            if values.ndim == 3:
                contributions = values[0]
                if contributions.shape[-1] == 2:
                    contributions = contributions[:, 1]
            else:
                contributions = values[0]

        # Build explanation items
        items = []
        for name, shap_val, feat_val in zip(
            self.feature_names, contributions, feature_vector, strict=False
        ):
            items.append(
                {
                    "feature": name,
                    "label": FEATURE_LABELS.get(name, name),
                    "value": round(float(feat_val), 4),
                    "shap_value": round(float(shap_val), 4),
                    "direction": "phishing" if shap_val > 0 else "legitimate",
                    "impact": "",  # filled below
                }
            )

        # Sort by absolute SHAP value (most impactful first)
        items.sort(key=lambda x: abs(x["shap_value"]), reverse=True)
        top_items = items[:top_n]

        # Assign impact level relative to top item
        if top_items:
            max_abs = max(abs(item["shap_value"]) for item in top_items) or 1.0
            for item in top_items:
                ratio = abs(item["shap_value"]) / max_abs
                if ratio >= 0.6:
                    item["impact"] = "high"
                elif ratio >= 0.3:
                    item["impact"] = "medium"
                else:
                    item["impact"] = "low"

        return top_items
