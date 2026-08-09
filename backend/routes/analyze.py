"""
analyze.py
==========
API route for POST /api/analyze — the core PhishGuard endpoint.

Accepts a URL, validates it, runs the ML prediction pipeline, and returns
a structured JSON result including the prediction, risk level, confidence
score, and SHAP-based feature explanations.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status

from backend.models.schemas import AnalyzeRequest, AnalyzeResponse, ErrorResponse
from backend.services.validator import URLValidationError, validate_url

router = APIRouter()


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
        503: {"description": "Model not loaded", "model": ErrorResponse},
    },
)
async def analyze_url(request: Request, body: AnalyzeRequest) -> AnalyzeResponse:
    """
    Analyze a URL and return a phishing prediction with explanation.

    The URL is:
    1. Validated for format and safety (no network requests made to it)
    2. Passed through the feature extractor (25 URL-based features)
    3. Classified by the trained XGBoost model
    4. Explained using SHAP TreeExplainer values

    Args:
        request: FastAPI request object (used to access app state).
        body:    Validated request body containing the URL.

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
        )

    # Check model is available
    predictor = request.app.state.predictor
    if not predictor.is_loaded:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "MODEL_UNAVAILABLE",
                "message": (
                    "The ML model is not loaded. "
                    "Please train the model using the notebook and restart the server."
                ),
            },
        )

    # Run prediction
    try:
        result = predictor.predict(validated_url)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "PREDICTION_FAILED",
                "message": "An unexpected error occurred during prediction.",
            },
        )

    return AnalyzeResponse(**result)
