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
from app.core.logging_config import setup_logging
from app.core.redis_client import get_client as get_redis, setup_redis, close_redis

setup_logging()
logger = logging.getLogger(__name__)


def _get_client_ip(request: Request) -> str:
    """
    Extract the real client IP, handling reverse proxies.

    When TRUSTED_PROXY_COUNT > 0, parse X-Forwarded-For and strip that
    many proxy hops from the right to reach the original client address.

    Example with TRUSTED_PROXY_COUNT=1:
        X-Forwarded-For: 203.0.113.5, 10.0.0.1
        Rightmost hop (10.0.0.1) is the proxy itself — real client is 203.0.113.5.

    Only set TRUSTED_PROXY_COUNT > 0 when a real trusted proxy is confirmed
    in front of this server. Without a proxy, clients can forge the header
    and bypass rate limiting.
    """
    if settings.TRUSTED_PROXY_COUNT > 0:
        xff = request.headers.get("X-Forwarded-For", "").strip()
        if xff:
            hops = [h.strip() for h in xff.split(",") if h.strip()]
            idx = max(0, len(hops) - settings.TRUSTED_PROXY_COUNT - 1)
            ip = hops[idx]
            if ":" in ip and not ip.startswith("["):
                ip, _, _ = ip.rpartition(":")
            if ip:
                return ip
    return request.client.host if request.client else "unknown"


# ── Rate Limiter ──────────────────────────────────────────────
# Uses Redis when available (shared across server instances; survives
# process restarts as long as the Redis container itself is not recreated).
# Falls back to in-memory when Redis is not configured or unreachable.

class RateLimiter:
    """
    Per-IP sliding window rate limiter.

    Redis mode  : uses a sorted set per IP; atomic and persistent.
    Fallback mode: in-memory defaultdict; resets on server restart.
    """

    def __init__(self, max_requests: int, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window = window_seconds
        self._requests: dict[str, list[float]] = defaultdict(list)

    async def is_allowed(self, client_ip: str) -> bool:
        redis = get_redis()
        if redis is not None:
            return await self._redis_is_allowed(redis, client_ip)
        return self._memory_is_allowed(client_ip)

    async def retry_after(self, client_ip: str) -> int:
        redis = get_redis()
        if redis is not None:
            return await self._redis_retry_after(redis, client_ip)
        return self._memory_retry_after(client_ip)

    # ── Redis implementation ──────────────────────────────────

    async def _redis_is_allowed(self, redis, client_ip: str) -> bool:
        key = f"rate:{client_ip}"
        now = time.time()
        window_start = now - self.window
        try:
            pipe = redis.pipeline()
            # Remove timestamps outside the current window
            await pipe.zremrangebyscore(key, "-inf", window_start)
            # Count remaining requests in window
            await pipe.zcard(key)
            # Add current request timestamp
            await pipe.zadd(key, {str(now): now})
            # Reset TTL so the key expires after the window
            await pipe.expire(key, self.window)
            results = await pipe.execute()
            count_before = results[1]
            return count_before < self.max_requests
        except Exception as e:
            logger.warning("Redis rate limit check failed: %s — falling back to allow", e)
            return True

    async def _redis_retry_after(self, redis, client_ip: str) -> int:
        key = f"rate:{client_ip}"
        try:
            oldest = await redis.zrange(key, 0, 0, withscores=True)
            if oldest:
                oldest_ts = oldest[0][1]
                return max(1, int(self.window - (time.time() - oldest_ts)))
        except Exception:
            pass
        return self.window

    # ── In-memory fallback ────────────────────────────────────

    def _memory_is_allowed(self, client_ip: str) -> bool:
        now = time.time()
        window_start = now - self.window
        self._requests[client_ip] = [
            t for t in self._requests[client_ip] if t > window_start
        ]
        if len(self._requests[client_ip]) >= self.max_requests:
            return False
        self._requests[client_ip].append(now)
        return True

    def _memory_retry_after(self, client_ip: str) -> int:
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

    # ── Redis ─────────────────────────────────────────────────────
    await setup_redis(settings.REDIS_URL)

    from app.services.ml.predictor import predictor  # noqa: F401

    logger.info("ML models loaded: %s", predictor.loaded)
    if settings.API_KEY:
        logger.info("API key authentication: ENABLED")
    else:
        logger.warning("API key authentication: DISABLED (set API_KEY env var for production)")
    logger.info("Rate limit: %d req/min per IP", settings.RATE_LIMIT_PER_MINUTE)

    # ── Browser Analysis Container ────────────────────────────
    if settings.BROWSER_ANALYSIS_ENABLED:
        from app.services.browser_analyzer import container_manager
        browser_ok = await container_manager.start()
        if browser_ok:
            logger.info("Browser analysis: ENABLED (container running)")
        else:
            logger.warning(
                "Browser analysis: DEGRADED — container could not be started. "
                "Install Docker and docker-py, or set BROWSER_ANALYSIS_ENABLED=false. "
                "The server will continue without browser analysis."
            )
    else:
        logger.info("Browser analysis: DISABLED (BROWSER_ANALYSIS_ENABLED=false)")

    yield

    # ── Shutdown ──────────────────────────────────────────────
    if settings.BROWSER_ANALYSIS_ENABLED:
        from app.services.browser_analyzer import container_manager
        await container_manager.stop()
    await close_redis()
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
        client_ip = _get_client_ip(request)
        if not await rate_limiter.is_allowed(client_ip):
            retry_after = await rate_limiter.retry_after(client_ip)
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
