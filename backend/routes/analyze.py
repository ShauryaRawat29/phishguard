"""
analyze.py
==========
API route for POST /api/analyze — the core PhishGuard endpoint.

Accepts a URL, validates it, runs the ML prediction pipeline, and returns
a structured JSON result including the prediction, risk level, confidence
score, and SHAP-based feature explanations.

NOTE: This endpoint is intentionally a sync `def`. FastAPI runs sync
endpoints in its threadpool, so CPU-bound work (feature extraction + SHAP)
never blocks the event loop.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status

from backend.dependencies import get_predictor
from backend.logging import get_logger
from backend.models.schemas import AnalyzeRequest, AnalyzeResponse, ErrorResponse
from backend.rate_limit import analyze_limit, limiter
from backend.services.predictor import PhishGuardPredictor
from backend.services.validator import URLValidationError, validate_url

router = APIRouter()
logger = get_logger(__name__)


@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    summary="Analyze a URL for phishing indicators",
    description=(
        "Submit a URL to the PhishGuard ML model. "
        "Returns a classification (PHISHING or LEGITIMATE), a risk level, "
        "a confidence score, and an explanation of the top contributing features."
    ),
    responses={
        200: {"description": "Successful prediction", "model": AnalyzeResponse},
        400: {"description": "URL too long or unsafe", "model": ErrorResponse},
        422: {"description": "Invalid URL format", "model": ErrorResponse},
        429: {"description": "Too many requests (rate limited)", "model": ErrorResponse},
        503: {"description": "Model not loaded", "model": ErrorResponse},
    },
)
@limiter.limit(analyze_limit())
def analyze_url(
    request: Request,
    body: AnalyzeRequest,
    predictor: Annotated[PhishGuardPredictor, Depends(get_predictor)],
) -> AnalyzeResponse:
    """
    Analyze a URL and return a phishing prediction with explanation.

    The URL is:
    1. Validated for format and safety (no network requests made to it)
    2. Passed through the feature extractor (33 URL-based features)
    3. Classified by the trained XGBoost model
    4. Explained using SHAP TreeExplainer values

    Args:
        request:  FastAPI request object (used for rate limiting).
        body:     Validated request body containing the URL.
        predictor: The shared model service (injected via Depends).

    Returns:
        AnalyzeResponse with prediction, risk level, confidence, and explanation.
    """
    # Validate URL
    try:
        validated_url = validate_url(body.url)
    except URLValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": e.code, "message": e.message, "input": body.url},
        ) from e

    # Check model is available
    if not predictor.is_loaded:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "MODEL_UNAVAILABLE",
                "message": (
                    "The ML model is not loaded. "
                    "Run `python scripts/rebuild_model.py` and restart the server."
                ),
            },
        )

    # Run prediction
    try:
        result = predictor.predict(validated_url)
    except Exception:
        logger.exception("Prediction failed for URL: %s", validated_url)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "PREDICTION_FAILED",
                "message": "An unexpected error occurred during prediction.",
            },
        ) from None

    return AnalyzeResponse(**result)
