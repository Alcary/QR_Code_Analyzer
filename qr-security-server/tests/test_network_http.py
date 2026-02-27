"""
Integration tests for NetworkInspector._check_http().

All network I/O is mocked. Tests exercise:
  - SSRF blocking on the initial URL
  - SSRF blocking mid-redirect (P0-2)
  - Normal 200 response
  - Single redirect (same domain)
  - Cross-domain redirect sets redirect_domain_mismatch
  - Exceeding MAX_REDIRECTS sets error="too_many_redirects"
  - Content flag detection
  - TLS verification failure surfaces as ssl_verification_failed error
"""

import asyncio
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import aiohttp

from app.services.network_inspector import NetworkInspector

# ── Test fixture helpers ──────────────────────────────────────


class _FakeResponse:
    """Minimal aiohttp response replacement usable as an async context manager."""

    def __init__(self, status: int, headers: dict | None = None, body: bytes = b""):
        self.status = status
        self._raw_headers = headers or {}
        self._body = body
        # url attribute mimics aiohttp's URL object
        self.url = MagicMock(__str__=MagicMock(return_value="https://example.com"))
        self.content = AsyncMock()
        self.content.read = AsyncMock(return_value=body)

    def headers_get(self, key: str, default=None):
        return self._raw_headers.get(key, default)

    async def __aenter__(self):
        # Expose .headers as an object with a .get() method
        self.headers = MagicMock(get=self.headers_get)
        return self

    async def __aexit__(self, *_):
        pass


class _FakeSession:
    """Fake aiohttp.ClientSession that yields pre-configured responses in order."""

    def __init__(self, responses: list[_FakeResponse]):
        self._queue = list(responses)

    def get(self, url: str, **_kwargs) -> _FakeResponse:
        return self._queue.pop(0)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        pass


def _patch_ssrf(return_value: bool):
    """Patch _is_private_or_reserved to a fixed return value."""
    return patch(
        "app.services.network_inspector._is_private_or_reserved",
        return_value=return_value,
    )


def _patch_session(responses: list[_FakeResponse]):
    """Patch aiohttp.ClientSession with a _FakeSession."""
    fake = _FakeSession(responses)
    return patch("aiohttp.ClientSession", return_value=fake)


# ── Tests ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_ssrf_blocked_on_initial_url():
    """If the initial hostname resolves to a private IP, return immediately."""
    inspector = NetworkInspector()
    with _patch_ssrf(True):
        result = await inspector._check_http("http://10.0.0.1/admin", "10.0.0.1")
    assert result.error == "ssrf_blocked"
    assert result.status_code is None


@pytest.mark.asyncio
async def test_ssrf_check_failure_blocks_request():
    """If _is_private_or_reserved raises, return error="ssrf_check_failed"."""
    inspector = NetworkInspector()
    with patch(
        "app.services.network_inspector._is_private_or_reserved",
        side_effect=OSError("DNS exploded"),
    ):
        result = await inspector._check_http("https://example.com", "example.com")
    assert result.error == "ssrf_check_failed"


@pytest.mark.asyncio
async def test_normal_200_response():
    """A clean 200 response populates status_code and final_url."""
    inspector = NetworkInspector()
    resp = _FakeResponse(200, {"Content-Type": "text/plain"})
    with _patch_ssrf(False), _patch_session([resp]):
        result = await inspector._check_http("https://example.com", "example.com")
    assert result.error is None
    assert result.status_code == 200
    assert result.redirect_count == 0


@pytest.mark.asyncio
async def test_single_redirect_same_domain_followed():
    """A 301 redirect is followed and the final response is captured."""
    inspector = NetworkInspector()
    redirect_resp = _FakeResponse(301, {"Location": "https://example.com/final"})
    final_resp = _FakeResponse(200, {"Content-Type": "text/html"})
    with _patch_ssrf(False), _patch_session([redirect_resp, final_resp]):
        result = await inspector._check_http("https://example.com/start", "example.com")
    assert result.error is None
    assert result.status_code == 200
    assert result.redirect_count == 1


@pytest.mark.asyncio
async def test_cross_domain_redirect_sets_flag():
    """A redirect to a different registered domain sets redirect_domain_mismatch."""
    inspector = NetworkInspector()
    redirect_resp = _FakeResponse(302, {"Location": "https://malicious.com/page"})
    # The final response URL will stringify to the malicious domain
    final_resp = _FakeResponse(200, {"Content-Type": "text/html"})
    final_resp.url = MagicMock(__str__=MagicMock(return_value="https://malicious.com/page"))

    with _patch_ssrf(False), _patch_session([redirect_resp, final_resp]):
        result = await inspector._check_http("https://example.com", "example.com")
    assert result.redirect_domain_mismatch is True


@pytest.mark.asyncio
async def test_too_many_redirects():
    """After MAX_REDIRECTS hops, return error='too_many_redirects'."""
    inspector = NetworkInspector()
    MAX_REDIRECTS = 10
    # Build MAX_REDIRECTS + 1 redirect responses (the +1 triggers the limit)
    redirect_resps = [
        _FakeResponse(301, {"Location": f"https://example.com/hop{i}"})
        for i in range(MAX_REDIRECTS + 1)
    ]
    with _patch_ssrf(False), _patch_session(redirect_resps):
        result = await inspector._check_http("https://example.com/start", "example.com")
    assert result.error == "too_many_redirects"
    assert result.redirect_count == MAX_REDIRECTS + 1


@pytest.mark.asyncio
async def test_ssrf_blocked_on_redirect_hop():
    """
    After the initial URL passes, if a redirect destination resolves to a
    private IP, the request must be blocked (P0-2).
    """
    inspector = NetworkInspector()
    redirect_resp = _FakeResponse(301, {"Location": "http://169.254.169.254/latest/meta-data/"})

    # First call (initial URL): not private. Second call (redirect hop): private.
    side_effects = [False, True]
    call_count = 0

    def _ssrf_side_effect(hostname: str) -> bool:
        nonlocal call_count
        result = side_effects[min(call_count, len(side_effects) - 1)]
        call_count += 1
        return result

    with (
        patch(
            "app.services.network_inspector._is_private_or_reserved",
            side_effect=_ssrf_side_effect,
        ),
        _patch_session([redirect_resp]),
    ):
        result = await inspector._check_http(
            "https://example.com/redirect", "example.com"
        )

    assert result.error == "ssrf_blocked"


@pytest.mark.asyncio
async def test_content_flag_password_field():
    """HTML body containing a password field is detected and flagged."""
    inspector = NetworkInspector()
    body = b'<html><form><input type="password" name="password"></form></html>'
    resp = _FakeResponse(200, {"Content-Type": "text/html; charset=utf-8"}, body)
    with _patch_ssrf(False), _patch_session([resp]):
        result = await inspector._check_http("https://example.com/login", "example.com")
    assert "password_field" in result.content_flags


@pytest.mark.asyncio
async def test_tls_error_sets_ssl_verification_failed():
    """An aiohttp ClientConnectorSSLError surfaces as error='ssl_verification_failed'.

    aiohttp raises ClientConnectorSSLError inside the __aenter__ of the
    response context manager (i.e. when the TCP+TLS handshake actually runs),
    so we trigger it at that point.
    """
    inspector = NetworkInspector()

    ssl_error = aiohttp.ClientConnectorSSLError(
        connection_key=MagicMock(), os_error=OSError("cert verify failed")
    )

    # response context manager whose __aenter__ raises the SSL error
    mock_resp_cm = MagicMock()
    mock_resp_cm.__aenter__ = AsyncMock(side_effect=ssl_error)
    mock_resp_cm.__aexit__ = AsyncMock(return_value=False)

    # session whose .get() call returns that context manager
    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_resp_cm)

    with _patch_ssrf(False), patch("aiohttp.ClientSession") as mock_cls:
        mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        result = await inspector._check_http("https://bad-tls.example.com", "example.com")

    assert result.error == "ssl_verification_failed"
