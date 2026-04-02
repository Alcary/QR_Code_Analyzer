"""
Redis Client

Provides a shared async Redis connection used by the cache and rate limiter.
If Redis is not configured (REDIS_URL is empty) or unreachable, both
components fall back to their in-memory implementations automatically —
the server always starts regardless of Redis availability.
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Module-level client — initialised once in setup_redis(), reused everywhere.
_client: Any = None


async def setup_redis(redis_url: str) -> bool:
    """
    Connect to Redis. Returns True if the connection succeeded.
    Called once at application startup from main.py lifespan.
    """
    global _client

    if not redis_url:
        logger.info("Redis: not configured (REDIS_URL is empty) — using in-memory fallback")
        return False

    try:
        import redis.asyncio as redis
        client = redis.from_url(redis_url, decode_responses=True)
        await client.ping()
        _client = client
        logger.info("Redis: connected to %s", redis_url)
        return True
    except Exception as e:
        logger.warning("Redis: could not connect (%s) — using in-memory fallback", e)
        _client = None
        return False


async def close_redis() -> None:
    """Close the Redis connection. Called at application shutdown."""
    global _client
    if _client is not None:
        try:
            await _client.aclose()
        except Exception:
            pass
        _client = None
        logger.info("Redis: connection closed")


def get_client() -> Any:
    """Return the Redis client, or None if Redis is not available."""
    return _client
