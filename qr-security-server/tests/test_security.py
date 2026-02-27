"""
Tests for:
- _get_client_ip() X-Forwarded-For parsing (app/main.py)
- verify_api_key() one-time warning deduplication (app/core/security.py)
"""

import logging
from unittest.mock import MagicMock, patch

import pytest

import app.core.security as security_module
from app.main import _get_client_ip


# ── Helpers ───────────────────────────────────────────────────


def _make_request(xff: str | None = None, client_host: str = "1.2.3.4") -> MagicMock:
    """Build a minimal fake FastAPI Request."""
    req = MagicMock()
    req.client.host = client_host
    headers = MagicMock()
    headers.get = lambda key, default="": (
        xff if xff is not None and key.lower() == "x-forwarded-for" else default
    )
    req.headers = headers
    return req


def _with_proxy_count(n: int):
    """Patch settings.TRUSTED_PROXY_COUNT for the duration of a test."""
    return patch("app.main.settings.TRUSTED_PROXY_COUNT", n)


# ── _get_client_ip ────────────────────────────────────────────


def test_no_proxy_returns_client_host():
    req = _make_request(client_host="10.0.0.1")
    with _with_proxy_count(0):
        assert _get_client_ip(req) == "10.0.0.1"


def test_proxy_count_1_returns_first_hop():
    """XFF: client, proxy → real client is index 0."""
    req = _make_request(xff="203.0.113.5, 10.0.0.1")
    with _with_proxy_count(1):
        assert _get_client_ip(req) == "203.0.113.5"


def test_proxy_count_2_returns_first_hop():
    """XFF: client, proxy1, proxy2 → real client is index 0."""
    req = _make_request(xff="203.0.113.5, 10.0.0.1, 10.0.0.2")
    with _with_proxy_count(2):
        assert _get_client_ip(req) == "203.0.113.5"


def test_proxy_count_2_middle_client():
    """XFF: trusted_client, proxy1, proxy2 → picks the correct middle entry."""
    req = _make_request(xff="1.1.1.1, 2.2.2.2, 10.0.0.1, 10.0.0.2")
    with _with_proxy_count(2):
        # idx = max(0, 4 - 2 - 1) = 1 → hops[1] = "2.2.2.2"
        assert _get_client_ip(req) == "2.2.2.2"


def test_fewer_hops_than_trusted_count_clamps_to_first():
    """If XFF has fewer entries than TRUSTED_PROXY_COUNT, clamp to hops[0]."""
    req = _make_request(xff="203.0.113.5")
    with _with_proxy_count(5):
        assert _get_client_ip(req) == "203.0.113.5"


def test_proxy_enabled_but_empty_xff_falls_back():
    """Empty X-Forwarded-For with TRUSTED_PROXY_COUNT > 0 falls back to client.host."""
    req = _make_request(xff="", client_host="5.5.5.5")
    with _with_proxy_count(1):
        assert _get_client_ip(req) == "5.5.5.5"


def test_whitespace_trimmed_from_hops():
    """Extra whitespace around hop entries is stripped."""
    req = _make_request(xff="  203.0.113.5  ,   10.0.0.1  ")
    with _with_proxy_count(1):
        assert _get_client_ip(req) == "203.0.113.5"


def test_no_client_and_no_xff_returns_unknown():
    req = MagicMock()
    req.client = None
    headers = MagicMock()
    headers.get = lambda key, default="": default
    req.headers = headers
    with _with_proxy_count(0):
        assert _get_client_ip(req) == "unknown"


# ── verify_api_key — one-time warning ────────────────────────


@pytest.fixture(autouse=False)
def reset_api_key_warned():
    """Reset the module-level flag before/after each security warning test."""
    original = security_module._no_key_warned
    security_module._no_key_warned = False
    yield
    security_module._no_key_warned = original


@pytest.mark.asyncio
async def test_api_key_warning_emitted_once(reset_api_key_warned, caplog):
    """With API_KEY unset, the warning must appear exactly once over N calls."""
    with patch.object(security_module.settings, "API_KEY", ""):
        with caplog.at_level(logging.WARNING, logger="app.core.security"):
            result1 = await security_module.verify_api_key(None)
            result2 = await security_module.verify_api_key(None)
            result3 = await security_module.verify_api_key(None)

    assert result1 == result2 == result3 == "dev"
    warning_msgs = [r.message for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warning_msgs) == 1, (
        f"Expected exactly 1 warning, got {len(warning_msgs)}: {warning_msgs}"
    )


@pytest.mark.asyncio
async def test_api_key_warning_not_emitted_when_key_is_set(reset_api_key_warned, caplog):
    """When API_KEY is set, no dev-mode warning is emitted."""
    with patch.object(security_module.settings, "API_KEY", "supersecretkey"):
        with caplog.at_level(logging.WARNING, logger="app.core.security"):
            # valid key
            result = await security_module.verify_api_key("supersecretkey")
    assert result == "supersecretkey"
    assert not caplog.records
