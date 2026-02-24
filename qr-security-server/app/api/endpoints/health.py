"""
Health Check Endpoint

Provides a /health endpoint that reports:
- Server status
- ML model load status
- Uptime
"""

import logging
import time
from fastapi import APIRouter

from app.services.ml.predictor import predictor

logger = logging.getLogger(__name__)
router = APIRouter()

_start_time = time.time()


@router.get("/health")
async def health_check():
    """
    Health check endpoint for monitoring and load balancers.

    Returns model load status, uptime, and component health.
    """
    uptime_seconds = int(time.time() - _start_time)

    ml_status = "loaded" if predictor.loaded else "unavailable"
    ml_components = []
    if predictor.xgb_model is not None:
        ml_components.append("xgboost")

    return {
        "status": "healthy",
        "uptime_seconds": uptime_seconds,
        "ml": {
            "status": ml_status,
            "components": ml_components,
            "feature_count": len(predictor.feature_names),
        },
    }
