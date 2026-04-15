"""
Tests for app/services/tranco_client.py.

All tests mock Redis and the Tranco HTTP API so no network calls are made.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ── _get_rank — Redis cache read ──────────────────────────────────


@pytest.mark.asyncio
async def test_cache_hit_returns_rank():
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value="42000")

    with patch("app.services.tranco_client.get_redis", return_value=mock_redis):
        with patch("app.services.tranco_client._fetch_rank") as mock_fetch:
            from app.services.tranco_client import _get_rank
            result = await _get_rank("example.com")

    assert result == 42000
    mock_fetch.assert_not_called()


@pytest.mark.asyncio
# 'none' string in Redis is the sentinel for a previously confirmed unranked domain
async def test_cache_hit_none_sentinel_returns_none():
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value="none")

    with patch("app.services.tranco_client.get_redis", return_value=mock_redis):
        with patch("app.services.tranco_client._fetch_rank") as mock_fetch:
            from app.services.tranco_client import _get_rank
            result = await _get_rank("example.com")

    assert result is None
    mock_fetch.assert_not_called()


@pytest.mark.asyncio
async def test_cache_miss_calls_api_and_caches_result():
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=None)
    mock_redis.setex = AsyncMock()

    with patch("app.services.tranco_client.get_redis", return_value=mock_redis):
        with patch("app.services.tranco_client._fetch_rank", AsyncMock(return_value=5000)):
            from app.services.tranco_client import _get_rank
            result = await _get_rank("google.com")

    assert result == 5000
    mock_redis.setex.assert_called_once()
    args = mock_redis.setex.call_args[0]
    assert args[0] == "tranco:google.com"
    assert args[2] == "5000"


@pytest.mark.asyncio
# unranked domains are stored as 'none' so a later cache hit returns None without hitting the API
async def test_cache_miss_unranked_domain_stores_none_sentinel():
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=None)
    mock_redis.setex = AsyncMock()

    with patch("app.services.tranco_client.get_redis", return_value=mock_redis):
        with patch("app.services.tranco_client._fetch_rank", AsyncMock(return_value=None)):
            from app.services.tranco_client import _get_rank
            result = await _get_rank("obscure.example")

    assert result is None
    stored_value = mock_redis.setex.call_args[0][2]
    assert stored_value == "none"


@pytest.mark.asyncio
async def test_redis_error_falls_through_to_api():
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(side_effect=ConnectionError("redis down"))

    with patch("app.services.tranco_client.get_redis", return_value=mock_redis):
        with patch("app.services.tranco_client._fetch_rank", AsyncMock(return_value=1234)) as mock_fetch:
            from app.services.tranco_client import _get_rank
            result = await _get_rank("example.com")

    assert result == 1234
    mock_fetch.assert_called_once()


@pytest.mark.asyncio
async def test_no_redis_calls_api_directly():
    with patch("app.services.tranco_client.get_redis", return_value=None):
        with patch("app.services.tranco_client._fetch_rank", AsyncMock(return_value=7777)) as mock_fetch:
            from app.services.tranco_client import _get_rank
            result = await _get_rank("example.com")

    assert result == 7777
    mock_fetch.assert_called_once_with("example.com")


# ── get_tranco_dampening — tier logic ─────────────────────────────


@pytest.mark.asyncio
async def test_top_10k_returns_015():
    with patch("app.services.tranco_client._get_rank", AsyncMock(return_value=1)):
        from app.services.tranco_client import get_tranco_dampening
        assert await get_tranco_dampening("google.com") == pytest.approx(0.15)


@pytest.mark.asyncio
async def test_rank_10000_boundary_returns_015():
    with patch("app.services.tranco_client._get_rank", AsyncMock(return_value=10_000)):
        from app.services.tranco_client import get_tranco_dampening
        assert await get_tranco_dampening("example.com") == pytest.approx(0.15)


@pytest.mark.asyncio
async def test_top_100k_returns_035():
    with patch("app.services.tranco_client._get_rank", AsyncMock(return_value=50_000)):
        from app.services.tranco_client import get_tranco_dampening
        assert await get_tranco_dampening("example.com") == pytest.approx(0.35)


@pytest.mark.asyncio
async def test_rank_100000_boundary_returns_035():
    with patch("app.services.tranco_client._get_rank", AsyncMock(return_value=100_000)):
        from app.services.tranco_client import get_tranco_dampening
        assert await get_tranco_dampening("example.com") == pytest.approx(0.35)


@pytest.mark.asyncio
async def test_outside_top_100k_returns_none():
    with patch("app.services.tranco_client._get_rank", AsyncMock(return_value=500_000)):
        from app.services.tranco_client import get_tranco_dampening
        assert await get_tranco_dampening("example.com") is None


@pytest.mark.asyncio
async def test_unranked_domain_returns_none():
    with patch("app.services.tranco_client._get_rank", AsyncMock(return_value=None)):
        from app.services.tranco_client import get_tranco_dampening
        assert await get_tranco_dampening("obscure.example") is None


@pytest.mark.asyncio
async def test_empty_domain_returns_none_without_lookup():
    with patch("app.services.tranco_client._get_rank") as mock_rank:
        from app.services.tranco_client import get_tranco_dampening
        assert await get_tranco_dampening("") is None
    mock_rank.assert_not_called()
