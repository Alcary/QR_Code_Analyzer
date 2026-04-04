"""
Tranco rank lookup service.

Queries the Tranco top-1M API per domain and caches the result in Redis
for 24 hours. On a cache miss the API is called; on a cache hit the result
is returned instantly without a network round-trip.

Tranco: https://tranco-list.eu/
API:    GET https://tranco-list.eu/api/ranks/domain/{domain}
        → {"ranks": [{"list": "YYYY-MM-DD", "rank": N}]}

Dampening tiers applied in analyzer.py:
    rank ≤  10_000  → 0.15  (globally top-tier traffic, near-zero phishing risk)
    rank ≤ 100_000  → 0.35  (high traffic, low phishing risk)
    not ranked      → None  (fall through to existing computed dampening)
"""

import logging

import aiohttp

from app.core.redis_client import get_client as get_redis

logger = logging.getLogger(__name__)

_TRANCO_API   = "https://tranco-list.eu/api/ranks/domain/{domain}"
_CACHE_TTL    = 86_400          # 24 hours in seconds
_CACHE_PREFIX = "tranco:"

_TIER_TOP_10K  = (10_000,  0.15)
_TIER_TOP_100K = (100_000, 0.35)


async def get_tranco_dampening(registered_domain: str) -> float | None:
    """
    Return a Tranco-based dampening factor for *registered_domain*, or
    ``None`` if the domain is not in the top 100k (caller uses its own
    computed dampening in that case).

    Never raises — all errors are caught and logged.
    """
    if not registered_domain:
        return None

    rank = await _get_rank(registered_domain)
    if rank is None:
        return None

    if rank <= _TIER_TOP_10K[0]:
        logger.info("Tranco rank %d (top 10k) for %s → dampening %.2f",
                    rank, registered_domain, _TIER_TOP_10K[1])
        return _TIER_TOP_10K[1]

    if rank <= _TIER_TOP_100K[0]:
        logger.info("Tranco rank %d (top 100k) for %s → dampening %.2f",
                    rank, registered_domain, _TIER_TOP_100K[1])
        return _TIER_TOP_100K[1]

    return None  # ranked but outside top 100k — use existing dampening


# ── Internal helpers ──────────────────────────────────────────────────────────

async def _get_rank(domain: str) -> int | None:
    """Return Tranco rank, checking Redis first then the API."""
    cache_key = f"{_CACHE_PREFIX}{domain}"
    redis = get_redis()

    if redis is not None:
        try:
            cached = await redis.get(cache_key)
            if cached is not None:
                val = cached.decode() if isinstance(cached, bytes) else str(cached)
                return int(val) if val != "none" else None
        except Exception as exc:
            logger.warning("Tranco Redis get failed for %s: %s", domain, exc)

    rank = await _fetch_rank(domain)

    if redis is not None:
        try:
            await redis.setex(
                cache_key,
                _CACHE_TTL,
                str(rank) if rank is not None else "none",
            )
        except Exception as exc:
            logger.warning("Tranco Redis set failed for %s: %s", domain, exc)

    return rank


async def _fetch_rank(domain: str) -> int | None:
    """Call the Tranco API. Returns the rank integer or None."""
    url = _TRANCO_API.format(domain=domain)
    try:
        async with aiohttp.ClientSession() as session, session.get(
            url, timeout=aiohttp.ClientTimeout(total=3)
        ) as resp:
            if resp.status != 200:
                logger.debug("Tranco API returned %d for %s", resp.status, domain)
                return None
            data = await resp.json()

        ranks = data.get("ranks", [])
        if not ranks:
            return None
        return int(ranks[0]["rank"])

    except aiohttp.ClientError as exc:
        logger.warning("Tranco API request failed for %s: %s", domain, exc)
        return None
    except Exception as exc:
        logger.warning("Tranco lookup unexpected error for %s: %s", domain, exc)
        return None
