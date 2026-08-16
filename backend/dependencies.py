"""
dependencies.py
===============
FastAPI dependency providers.

Centralizes how services are injected into routes. The predictor is loaded
once at application startup and held in `app.state`; routes receive it via
`Depends(get_predictor)` rather than reaching into `request.app.state`
themselves.
"""

from __future__ import annotations

from fastapi import Request

from backend.services.predictor import PhishGuardPredictor


def get_predictor(request: Request) -> PhishGuardPredictor:
    """
    Return the shared PhishGuardPredictor instance from app state.

    Args:
        request: The incoming FastAPI request.

    Returns:
        The predictor loaded during application startup.
    """
    return request.app.state.predictor
