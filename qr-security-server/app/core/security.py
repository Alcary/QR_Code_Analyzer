"""
API Key Authentication

Simple bearer-token authentication for the mobile app.
The API key is configured via the API_KEY environment variable.

Usage in endpoints:
    @router.post("/scan", dependencies=[Depends(verify_api_key)])
    async def scan_url(request: ScanRequest): ...
"""

import logging
import secrets
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader

from app.core.config import settings

logger = logging.getLogger(__name__)

# Header scheme: Authorization: Bearer <key>
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# Emit the "no API key" warning at most once per process so it doesn't
# spam the log on every request in dev mode.
_no_key_warned: bool = False


async def verify_api_key(api_key: str | None = Security(_api_key_header)) -> str:
    """
    Validate the API key from the X-API-Key header.

    If API_KEY is not set in config (dev mode), authentication is skipped
    with a one-time startup warning.
    """
    global _no_key_warned
    # Dev mode: no key configured → allow all (warn once)
    if not settings.API_KEY:
        if not _no_key_warned:
            logger.warning("API_KEY not set — authentication disabled (dev mode)")
            _no_key_warned = True
        return "dev"

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key. Provide X-API-Key header.",
        )

    if not secrets.compare_digest(api_key, settings.API_KEY):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key.",
        )

    return api_key
