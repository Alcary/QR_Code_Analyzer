"""
Tests for WHOISResult.lookup_failed sentinel (app/services/network_inspector.py).

Verifies that lookup_failed is set correctly across all failure modes and
is False on both a successful lookup and a lookup that returned no date.
All tests mock the blocking `whois.whois()` call so no real DNS/WHOIS
queries are made.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.network_inspector import NetworkInspector, WHOISResult


def _inspector() -> NetworkInspector:
    return NetworkInspector(http_timeout=8.0, whois_timeout=5.0)


# ── Successful lookups — lookup_failed must be False ─────────────


@pytest.mark.asyncio
async def test_successful_lookup_with_date_not_failed():
    """A clean WHOIS response with a creation date sets lookup_failed=False."""
    from datetime import datetime, timezone

    mock_w = MagicMock()
    mock_w.creation_date = datetime(2020, 1, 1, tzinfo=timezone.utc)
    mock_w.registrar = "Example Registrar"

    inspector = _inspector()
    with patch("whois.whois", return_value=mock_w):
        result = await inspector._check_whois("example.com")

    assert result.lookup_failed is False
    assert result.age_days is not None
    assert result.error is None


@pytest.mark.asyncio
async def test_successful_lookup_no_date_not_failed():
    """WHOIS succeeds but returns no creation date — lookup_failed stays False."""
    mock_w = MagicMock()
    mock_w.creation_date = None
    mock_w.registrar = "Some Registrar"

    inspector = _inspector()
    with patch("whois.whois", return_value=mock_w):
        result = await inspector._check_whois("example.com")

    assert result.lookup_failed is False
    assert result.age_days is None
    assert result.error is None


# ── Failure modes — lookup_failed must be True ────────────────────


@pytest.mark.asyncio
async def test_timeout_sets_lookup_failed():
    """asyncio.TimeoutError during WHOIS lookup sets lookup_failed=True."""
    inspector = _inspector()
    inspector.whois_timeout = 0.001  # force immediate timeout

    with patch("whois.whois", side_effect=lambda d: asyncio.sleep(10)):
        result = await inspector._check_whois("slow-domain.com")

    assert result.lookup_failed is True
    assert result.error == "whois_timeout"
    assert result.age_days is None


@pytest.mark.asyncio
async def test_generic_exception_sets_lookup_failed():
    """Any unexpected exception during lookup sets lookup_failed=True."""
    inspector = _inspector()
    with patch("whois.whois", side_effect=ConnectionRefusedError("no route to host")):
        result = await inspector._check_whois("unreachable.com")

    assert result.lookup_failed is True
    assert result.error is not None
    assert result.age_days is None


@pytest.mark.asyncio
async def test_whois_not_installed_sets_lookup_failed():
    """Missing python-whois library sets lookup_failed=True."""
    inspector = _inspector()
    with patch.dict("sys.modules", {"whois": None}):
        result = await inspector._check_whois("example.com")

    assert result.lookup_failed is True
    assert result.error == "whois_not_installed"


# ── Default value ─────────────────────────────────────────────────


def test_whoisresult_default_lookup_failed_is_false():
    """WHOISResult() initialises with lookup_failed=False."""
    r = WHOISResult()
    assert r.lookup_failed is False


def test_whoisresult_can_be_constructed_with_lookup_failed_true():
    r = WHOISResult(error="whois_timeout", lookup_failed=True)
    assert r.lookup_failed is True
    assert r.age_days is None
