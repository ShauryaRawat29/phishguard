"""
features.py
===========
API route for GET /api/features — static feature metadata.

Returns the ordered list of feature names and their human-readable labels so
the frontend can render the full feature vector without duplicating labels.

NOTE: This endpoint is intentionally a sync `def`. FastAPI runs sync
endpoints in its threadpool, so CPU-bound work (feature extraction + SHAP)
never blocks the event loop.
"""

from __future__ import annotations

from fastapi import APIRouter

from ml.explainer import FEATURE_LABELS
from ml.feature_extractor import FeatureExtractor

router = APIRouter()


@router.get(
    "/features",
    summary="List ML feature names and labels",
    description=(
        "Returns the ordered list of features used by the model along with a "
        "human-readable label for each. Used by the frontend to render the "
        "full feature breakdown."
    ),
)
def list_features() -> dict:
    """Return feature names in model order and their human-readable labels."""
    return {
        "feature_names": FeatureExtractor.FEATURE_NAMES,
        "feature_labels": {
            name: FEATURE_LABELS.get(name, name) for name in FeatureExtractor.FEATURE_NAMES
        },
    }
