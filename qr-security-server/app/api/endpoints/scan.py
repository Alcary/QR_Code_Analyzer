from fastapi import APIRouter
from app.models.schemas import ScanRequest, ScanResult
from app.services.analyzer import analyzer

router = APIRouter()

@router.post("/scan", response_model=ScanResult)
async def scan_url(request: ScanRequest):
    """
    Scans a given URL for security threats.
    """
    result = await analyzer.analyze(request.url)
    return ScanResult(
        status=result["status"],
        message=result["message"],
        details=result.get("details", {"original_url": request.url})
    )
