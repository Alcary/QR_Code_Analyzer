"""
Request Logging & Timing Middleware

Adds to every request:
- Unique request ID (X-Request-ID header)
- Request/response logging with timing
- Structured log output for production debugging
"""

import logging
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("app.middleware")


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Logs every request with:
    - Method, path, status code
    - Response time in ms
    - Unique request ID for tracing
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4())[:8])
        start = time.perf_counter()

        # Attach request_id to request state for use in handlers
        request.state.request_id = request_id

        logger.info(
            "[%s] → %s %s",
            request_id,
            request.method,
            request.url.path,
        )

        try:
            response = await call_next(request)
        except Exception:
            elapsed = int((time.perf_counter() - start) * 1000)
            logger.error(
                "[%s] ✗ %s %s — unhandled exception (%dms)",
                request_id,
                request.method,
                request.url.path,
                elapsed,
            )
            raise

        elapsed = int((time.perf_counter() - start) * 1000)
        logger.info(
            "[%s] ← %s %s — %d (%dms)",
            request_id,
            request.method,
            request.url.path,
            response.status_code,
            elapsed,
        )

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time"] = f"{elapsed}ms"
        return response
