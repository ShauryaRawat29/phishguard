"""
test_explainer.py
=================
Unit tests for the SHAP-based PhishGuardExplainer.

A tiny DecisionTreeClassifier is trained on toy data so the tests are fast
and deterministic — no pre-trained model artifact required.
Run with: pytest tests/test_explainer.py -v
"""

import numpy as np
from sklearn.tree import DecisionTreeClassifier

from ml.explainer import PhishGuardExplainer
from ml.feature_extractor import FeatureExtractor


def _make_explainer() -> PhishGuardExplainer:
    """Train a trivial tree and wrap it in a PhishGuardExplainer."""
    rng = np.random.default_rng(0)
    X = rng.integers(0, 2, size=(200, 3)).astype(float)
    y = np.where(X[:, 0] == 1, 1, 0)
    model = DecisionTreeClassifier(max_depth=3, random_state=42)
    model.fit(X, y)
    names = ["feat_a", "feat_b", "feat_c"]
    return PhishGuardExplainer(model, names)


def test_explain_returns_top_n_items():
    explainer = _make_explainer()
    items = explainer.explain([1.0, 0.0, 1.0], top_n=2)
    assert len(items) == 2


def test_explain_items_have_expected_keys():
    explainer = _make_explainer()
    items = explainer.explain([1.0, 0.0, 1.0], top_n=3)
    for item in items:
        for key in ("feature", "label", "value", "shap_value", "direction", "impact"):
            assert key in item, f"Missing key: {key}"
        assert item["direction"] in {"phishing", "legitimate"}
        assert item["impact"] in {"high", "medium", "low"}


def test_explain_sorted_by_abs_shap():
    explainer = _make_explainer()
    items = explainer.explain([1.0, 0.0, 1.0], top_n=3)
    abs_values = [abs(item["shap_value"]) for item in items]
    assert abs_values == sorted(abs_values, reverse=True)


def test_explain_respects_feature_names():
    explainer = _make_explainer()
    items = explainer.explain([1.0, 0.0, 1.0], top_n=3)
    features = {item["feature"] for item in items}
    assert features <= {"feat_a", "feat_b", "feat_c"}


def test_feature_labels_cover_all_extractor_features():
    from ml.explainer import FEATURE_LABELS

    missing = [name for name in FeatureExtractor.FEATURE_NAMES if name not in FEATURE_LABELS]
    assert missing == [], f"Missing human-readable labels: {missing}"
