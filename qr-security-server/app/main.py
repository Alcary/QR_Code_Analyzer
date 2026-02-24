import logging
from contextlib import asynccontextmanager
from collections import defaultdict
import time

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.endpoints import scan, health
from app.api.middleware import RequestLoggingMiddleware
from app.core.config import settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger(__name__)


# ── In-Memory Rate Limiter ────────────────────────────────────
# Simple sliding-window rate limiter. For production at scale,
# replace with Redis-backed solution (e.g., slowapi + redis).

class RateLimiter:
    """Per-IP sliding window rate limiter."""

    def __init__(self, max_requests: int, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window = window_seconds
        self._requests: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, client_ip: str) -> bool:
        now = time.time()
        window_start = now - self.window

        # Prune old entries
        self._requests[client_ip] = [
            t for t in self._requests[client_ip] if t > window_start
        ]

        if len(self._requests[client_ip]) >= self.max_requests:
            return False

        self._requests[client_ip].append(now)
        return True

    def retry_after(self, client_ip: str) -> int:
        """Seconds until the oldest request in the window expires."""
        if not self._requests[client_ip]:
            return 0
        oldest = min(self._requests[client_ip])
        return max(1, int(self.window - (time.time() - oldest)))


rate_limiter = RateLimiter(
    max_requests=settings.RATE_LIMIT_PER_MINUTE,
    window_seconds=60,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: validate config, load ML models."""

    # ── Production safety checks ──────────────────────────────
    if settings.ENVIRONMENT == "production":
        if not settings.API_KEY:
            raise RuntimeError(
                "ENVIRONMENT=production but API_KEY is empty. "
                "Set API_KEY in your .env file or environment variables."
            )
        if "*" in settings.BACKEND_CORS_ORIGINS:
            raise RuntimeError(
                "ENVIRONMENT=production but CORS allows '*'. "
                "Set BACKEND_CORS_ORIGINS to your app's specific origin."
            )
        logger.info("Running in PRODUCTION mode")
    else:
        logger.info("Running in DEV mode (relaxed security)")

    from app.services.ml.predictor import predictor  # noqa: F401

    logger.info("ML models loaded: %s", predictor.loaded)
    if settings.API_KEY:
        logger.info("API key authentication: ENABLED")
    else:
        logger.warning("API key authentication: DISABLED (set API_KEY env var for production)")
    logger.info("Rate limit: %d req/min per IP", settings.RATE_LIMIT_PER_MINUTE)
    yield
    logger.info("Shutting down")


app = FastAPI(title=settings.PROJECT_NAME, lifespan=lifespan)

# ── Middleware (order matters: last added = first executed) ────
app.add_middleware(RequestLoggingMiddleware)

if settings.BACKEND_CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.BACKEND_CORS_ORIGINS],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


# ── Rate Limiting Middleware ──────────────────────────────────

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Apply per-IP rate limiting to scan endpoints."""
    # Only rate-limit the scan endpoint, not health checks
    if request.url.path.endswith("/scan"):
        client_ip = request.client.host if request.client else "unknown"
        if not rate_limiter.is_allowed(client_ip):
            retry_after = rate_limiter.retry_after(client_ip)
            logger.warning("Rate limit exceeded for %s", client_ip)
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": f"Rate limit exceeded. Max {settings.RATE_LIMIT_PER_MINUTE} requests/minute.",
                    "retry_after": retry_after,
                },
                headers={"Retry-After": str(retry_after)},
            )
    return await call_next(request)


# ── Routes ────────────────────────────────────────────────────
app.include_router(scan.router, prefix=settings.API_V1_STR)
app.include_router(health.router, prefix=settings.API_V1_STR)


@app.get("/")
def read_root():
    return {"status": "ok", "service": settings.PROJECT_NAME}
