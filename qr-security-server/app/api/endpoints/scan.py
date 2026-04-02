import logging

from fastapi import APIRouter, Depends

from app.models.schemas import (
    ScanRequest,
    ScanResult,
    ScanDetails,
    MLDetails,
    DomainDetails,
    NetworkDetails,
    BrowserDetails,
)
from app.core.security import verify_api_key
from app.services.analyzer import analyzer

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/scan", response_model=ScanResult, dependencies=[Depends(verify_api_key)])
async def scan_url(request: ScanRequest):
    """
    Multi-layer URL security analysis.

    Pipeline: SSRF check → ML → browser render → DNS/SSL/WHOIS → verdict.
    Browser analysis is primary; DNS/SSL/HTTP/WHOIS runs as fallback when unavailable.
    """
    result = await analyzer.analyze(request.url)

    details = None
    raw = result.get("details")
    if raw:
        details = ScanDetails(
            ml=MLDetails(**raw["ml"]) if raw.get("ml") else None,
            domain=DomainDetails(**raw["domain"]) if raw.get("domain") else None,
            network=NetworkDetails(**raw["network"]) if raw.get("network") else None,
            browser=BrowserDetails(**raw["browser"]) if raw.get("browser") else None,
            risk_factors=raw.get("risk_factors", []),
            analysis_time_ms=raw.get("analysis_time_ms"),
        )

    return ScanResult(
        status=result["status"],
        message=result["message"],
        risk_score=result.get("risk_score", 0.0),
        details=details,
    )
