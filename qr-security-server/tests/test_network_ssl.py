"""Tests for HTTPS-port-aware SSL inspection in NetworkInspector.inspect_all()."""

from unittest.mock import AsyncMock

import pytest

from app.services.network_inspector import (
    DNSResult,
    HTTPResult,
    NetworkInspector,
    SSLResult,
    WHOISResult,
)


@pytest.mark.asyncio
async def test_inspect_all_passes_custom_https_port_to_ssl_check():
    inspector = NetworkInspector()
    inspector._check_dns = AsyncMock(return_value=DNSResult(resolved=True))
    inspector._check_ssl = AsyncMock(return_value=SSLResult(valid=True))
    inspector._check_http = AsyncMock(return_value=HTTPResult(status_code=200))
    inspector._check_whois = AsyncMock(return_value=WHOISResult())

    await inspector.inspect_all(
        "https://example.com:8443/login",
        "example.com",
        "example.com",
    )

    inspector._check_ssl.assert_awaited_once_with("example.com", 8443)


@pytest.mark.asyncio
async def test_inspect_all_skips_ssl_for_plain_http():
    inspector = NetworkInspector()
    inspector._check_dns = AsyncMock(return_value=DNSResult(resolved=True))
    inspector._check_ssl = AsyncMock(return_value=SSLResult(valid=True))
    inspector._check_http = AsyncMock(
        return_value=HTTPResult(status_code=200, scheme_warning=True)
    )
    inspector._check_whois = AsyncMock(return_value=WHOISResult())

    result = await inspector.inspect_all(
        "http://example.com/login",
        "example.com",
        "example.com",
    )

    inspector._check_ssl.assert_not_awaited()
    assert result.ssl.valid is None
    assert result.ssl.error == "not_applicable"
