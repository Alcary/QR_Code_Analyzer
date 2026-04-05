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

# SHA1 of the rate-limit Lua script, stored after SCRIPT LOAD at startup.
# None until setup_redis() succeeds; the rate limiter falls back to EVAL if unset.
_rate_limit_sha: str | None = None


async def setup_redis(redis_url: str) -> bool:
    """
    Connect to Redis and pre-load shared Lua scripts.
    Returns True if the connection succeeded.
    Called once at application startup from main.py lifespan.
    """
    global _client, _rate_limit_sha

    if not redis_url:
        logger.info("Redis: not configured (REDIS_URL is empty) — using in-memory fallback")
        return False

    try:
        import redis.asyncio as redis
        client = redis.from_url(redis_url, decode_responses=True)
        await client.ping()
        _client = client
        logger.info("Redis: connected to %s", redis_url)
    except Exception as e:
        logger.warning("Redis: could not connect (%s) — using in-memory fallback", e)
        _client = None
        return False

    return True


async def load_script(script: str) -> str | None:
    """
    Register a Lua script with Redis via SCRIPT LOAD and return its SHA1.

    The SHA1 can then be used with EVALSHA on every call, saving Redis
    the cost of parsing and compiling the script on each invocation.
    Redis retains the script until SCRIPT FLUSH or server restart; if
    the SHA is missing (e.g. after a Redis restart) callers should fall
    back to EVAL with the full script text.

    Returns None if Redis is not connected or SCRIPT LOAD fails.
    """
    if _client is None:
        return None
    try:
        sha = await _client.script_load(script)
        logger.info("Redis: script loaded (sha=%s)", sha)
        return sha
    except Exception as e:
        logger.warning("Redis: SCRIPT LOAD failed (%s) — callers will use EVAL", e)
        return None


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
