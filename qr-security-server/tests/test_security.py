"""
Tests for:
- _get_client_ip() X-Forwarded-For parsing (app/main.py)
- verify_api_key() one-time warning deduplication (app/core/security.py)
"""

import logging
from unittest.mock import MagicMock, patch

import pytest

import app.core.security as security_module
from app.core.config import Settings
from app.main import _get_client_ip, _strip_port


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


# XFF: client, proxy → real client is index 0
def test_proxy_count_1_returns_first_hop():
    req = _make_request(xff="203.0.113.5, 10.0.0.1")
    with _with_proxy_count(1):
        assert _get_client_ip(req) == "203.0.113.5"


# XFF: client, proxy1, proxy2 → real client is index 0
def test_proxy_count_2_returns_first_hop():
    req = _make_request(xff="203.0.113.5, 10.0.0.1, 10.0.0.2")
    with _with_proxy_count(2):
        assert _get_client_ip(req) == "203.0.113.5"


def test_proxy_count_2_middle_client():
    """XFF: trusted_client, proxy1, proxy2 → picks the correct middle entry."""
    req = _make_request(xff="1.1.1.1, 2.2.2.2, 10.0.0.1, 10.0.0.2")
    with _with_proxy_count(2):
        # idx = max(0, 4 - 2 - 1) = 1 → hops[1] = "2.2.2.2"
        assert _get_client_ip(req) == "2.2.2.2"


# XFF with fewer entries than TRUSTED_PROXY_COUNT → clamp to hops[0]
def test_fewer_hops_than_trusted_count_clamps_to_first():
    req = _make_request(xff="203.0.113.5")
    with _with_proxy_count(5):
        assert _get_client_ip(req) == "203.0.113.5"


def test_proxy_enabled_but_empty_xff_falls_back():
    req = _make_request(xff="", client_host="5.5.5.5")
    with _with_proxy_count(1):
        assert _get_client_ip(req) == "5.5.5.5"


def test_whitespace_trimmed_from_hops():
    req = _make_request(xff="  203.0.113.5  ,   10.0.0.1  ")
    with _with_proxy_count(1):
        assert _get_client_ip(req) == "203.0.113.5"


def test_ipv4_port_suffix_stripped():
    req = _make_request(xff="203.0.113.5:12345, 10.0.0.1")
    with _with_proxy_count(1):
        assert _get_client_ip(req) == "203.0.113.5"


def test_bracketed_ipv6_unwrapped():
    req = _make_request(xff="[2001:db8::1], 10.0.0.1")
    with _with_proxy_count(1):
        assert _get_client_ip(req) == "2001:db8::1"


# rpartition(':') would truncate bare IPv6 (e.g. '::1' → ''), must be handled specially
def test_bare_ipv6_loopback_not_mangled():
    req = _make_request(xff="::1, 10.0.0.1")
    with _with_proxy_count(1):
        assert _get_client_ip(req) == "::1"


def test_bare_ipv6_full_address_not_mangled():
    req = _make_request(xff="2001:db8::1, 10.0.0.1")
    with _with_proxy_count(1):
        assert _get_client_ip(req) == "2001:db8::1"


def test_bracketed_ipv6_with_port_stripped():
    req = _make_request(xff="[::1]:8080, 10.0.0.1")
    with _with_proxy_count(1):
        assert _get_client_ip(req) == "::1"


# ── _strip_port unit tests ────────────────────────────────────


@pytest.mark.parametrize(
    "raw,expected",
    [
        # bare IPv4
        ("203.0.113.5", "203.0.113.5"),
        # IPv4 with port
        ("203.0.113.5:8080", "203.0.113.5"),
        # bare IPv6 — was previously mangled to ":" or "2001:db8:"
        ("::1", "::1"),
        ("2001:db8::1", "2001:db8::1"),
        ("2606:4700:4700::1111", "2606:4700:4700::1111"),
        # bracketed IPv6 without port
        ("[::1]", "::1"),
        ("[2001:db8::1]", "2001:db8::1"),
        # bracketed IPv6 with port
        ("[::1]:8080", "::1"),
        ("[2001:db8::1]:443", "2001:db8::1"),
    ],
)
def test_strip_port(raw: str, expected: str):
    assert _strip_port(raw) == expected


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
    with patch.object(security_module.settings, "API_KEY", "supersecretkey"):
        with caplog.at_level(logging.WARNING, logger="app.core.security"):
            # valid key
            result = await security_module.verify_api_key("supersecretkey")
    assert result == "supersecretkey"
    assert not caplog.records


# ── API_KEY length validation (Settings) ─────────────────────


# empty string disables auth in dev mode — must be accepted by the validator
def test_api_key_empty_allowed():
    s = Settings(API_KEY="")
    assert s.API_KEY == ""


def test_api_key_32_chars_allowed():
    key = "a" * 32
    s = Settings(API_KEY=key)
    assert s.API_KEY == key


def test_api_key_long_allowed():
    key = "x" * 64
    s = Settings(API_KEY=key)
    assert s.API_KEY == key


def test_api_key_too_short_rejected():
    from pydantic import ValidationError
    with pytest.raises(ValidationError) as exc:
        Settings(API_KEY="short")
    assert "too short" in str(exc.value).lower()


# off-by-one: 31 chars is one under the minimum
def test_api_key_31_chars_rejected():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        Settings(API_KEY="a" * 31)


# ── RateLimiter._reload_script — lock serialisation ──────────


@pytest.mark.asyncio
# Many coroutines racing on NOSCRIPT must trigger load_script() exactly once;
# the lock + stale-SHA sentinel prevents redundant reloads.
async def test_reload_script_called_once_under_concurrent_noscript():
    import asyncio
    from unittest.mock import AsyncMock, patch
    from app.main import RateLimiter

    limiter = RateLimiter(max_requests=10)
    limiter._script_sha = "stale-sha"

    load_calls = 0

    async def fake_load_script(_script):
        nonlocal load_calls
        load_calls += 1
        await asyncio.sleep(0)  # yield so other coroutines can queue on the lock
        return "new-sha"

    with patch("app.main.load_script", side_effect=fake_load_script):
        # Simulate 10 coroutines all hitting NOSCRIPT simultaneously
        await asyncio.gather(*[limiter._reload_script() for _ in range(10)])

    assert load_calls == 1, f"Expected 1 load_script call, got {load_calls}"
    assert limiter._script_sha == "new-sha"


@pytest.mark.asyncio
# If load_script() returns None (Redis unreachable), SHA must be cleared so
# subsequent requests fall back to EVAL rather than using the stale SHA.
async def test_reload_script_updates_sha_to_none_when_redis_unavailable():
    from unittest.mock import patch
    from app.main import RateLimiter

    limiter = RateLimiter(max_requests=10)
    limiter._script_sha = "stale-sha"

    with patch("app.main.load_script", return_value=None):
        await limiter._reload_script()

    assert limiter._script_sha is None


@pytest.mark.asyncio
# If another coroutine refreshed the SHA while we waited on the lock, skip
# load_script() (stale-SHA sentinel). Simulated by pre-acquiring the lock,
# then changing the SHA before releasing — the task detects the change and returns early.
async def test_reload_script_skipped_when_sha_already_refreshed():
    import asyncio
    from unittest.mock import AsyncMock, patch
    from app.main import RateLimiter

    limiter = RateLimiter(max_requests=10)
    limiter._script_sha = "stale-sha"

    mock_load = AsyncMock(return_value="another-sha")

    with patch("app.main.load_script", mock_load):
        async with limiter._script_reload_lock:
            # Task captures stale_sha="stale-sha" then blocks waiting for the lock
            task = asyncio.create_task(limiter._reload_script())
            await asyncio.sleep(0)  # let it run until it blocks on the lock
            # Simulate another coroutine having already refreshed the SHA
            limiter._script_sha = "already-refreshed"
        # Lock released — task proceeds, detects SHA changed, skips load_script
        await task

    mock_load.assert_not_called()
    assert limiter._script_sha == "already-refreshed"
