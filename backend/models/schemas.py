"""
schemas.py
==========
Pydantic request and response schemas for the PhishGuard API.

Pydantic automatically validates incoming request data and serializes
outgoing response data. Invalid requests are rejected with a 422 error
before they ever reach business logic.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

# ─── Request Schemas ──────────────────────────────────────────────────────────


class AnalyzeRequest(BaseModel):
    """Request body for POST /api/analyze."""

    url: str = Field(
        ...,
        description="The URL to analyze for phishing indicators.",
        examples=["https://example.com/login"],
        min_length=4,
        max_length=2083,  # IE/browser maximum URL length
    )

    @field_validator("url")
    @classmethod
    def url_normalize(cls, v: str) -> str:
        """
        Normalize the URL before service-layer validation.

        Scheme enforcement (unsafe URI rejection, https auto-prepend) is
        handled centrally by `backend.services.validator.validate_url` so all
        clients get the same machine-readable error codes.
        """
        return v.strip()


# ─── Response Schemas ─────────────────────────────────────────────────────────


class ExplanationItem(BaseModel):
    """A single feature explanation item."""

    feature: str = Field(description="Internal feature name.")
    label: str = Field(description="Human-readable feature label.")
    value: float = Field(description="The raw feature value extracted from the URL.")
    shap_value: float = Field(description="SHAP contribution value (positive = phishing).")
    direction: Literal["phishing", "legitimate"] = Field(
        description="Whether this feature pushed the prediction toward phishing or legitimate."
    )
    impact: Literal["high", "medium", "low"] = Field(
        description="Relative impact level of this feature on the prediction."
    )


class AnalyzeResponse(BaseModel):
    """Response body for POST /api/analyze."""

    url: str = Field(description="The analyzed URL.")
    prediction: Literal["PHISHING", "LEGITIMATE"] = Field(
        description="The model's binary classification."
    )
    risk_level: Literal["HIGH", "MEDIUM", "LOW"] = Field(
        description="Categorical risk level derived from confidence score."
    )
    confidence: float = Field(
        description="Probability that the URL is phishing (0.0 to 1.0).",
        ge=0.0,
        le=1.0,
    )
    features: dict[str, float] = Field(description="All extracted feature values for this URL.")
    explanation: list[ExplanationItem] = Field(
        description="Top-N most influential features for this prediction."
    )
    timestamp: datetime = Field(description="UTC timestamp of the analysis.")


class HealthResponse(BaseModel):
    """Response body for GET /api/health."""

    status: Literal["ok", "degraded"] = Field(description="Service status.")
    model_loaded: bool = Field(description="Whether the ML model is loaded and ready.")
    version: str = Field(description="Application version string.")
    feature_count: int = Field(description="Number of URL features the model uses.")
    uptime_seconds: float = Field(description="Seconds since the process started.")
    model_metadata: dict[str, Any] | None = Field(
        default=None,
        description="Model training metadata (from models/model_metadata.json).",
    )


class ErrorResponse(BaseModel):
    """Standard error response body."""

    error: str = Field(description="Machine-readable error code.")
    message: str = Field(description="Human-readable error description.")
    input: str | None = Field(
        default=None,
        description="The input that caused the error (if applicable).",
    )
