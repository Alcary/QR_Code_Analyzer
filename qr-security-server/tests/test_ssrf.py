"""
Tests for SSRF protection (app/services/network_inspector.py).

_is_private_or_reserved() must block all RFC-1918 ranges, loopback,
link-local, carrier-grade NAT, and IPv6 private ranges.
These are pure synchronous tests — no network calls needed.
"""

import pytest

from app.services.network_inspector import _is_private_or_reserved


@pytest.mark.parametrize(
    "addr,should_block",
    [
        # ── IPv4 loopback ────────────────────────────────────
        ("127.0.0.1", True),
        ("127.255.255.255", True),
        # ── RFC 1918 private ──────────────────────────────────
        ("10.0.0.1", True),
        ("10.255.255.255", True),
        ("172.16.0.1", True),
        ("172.31.255.255", True),
        ("192.168.0.1", True),
        ("192.168.255.255", True),
        # ── Link-local (incl. AWS/Azure metadata endpoint) ────
        ("169.254.0.1", True),
        ("169.254.169.254", True),  # AWS instance metadata — critical SSRF target
        # ── Carrier-grade NAT ─────────────────────────────────
        ("100.64.0.1", True),
        ("100.127.255.255", True),
        # ── Reserved / TEST-NET ───────────────────────────────
        ("192.0.2.1", True),       # TEST-NET-1
        ("198.51.100.1", True),    # TEST-NET-2
        ("203.0.113.1", True),     # TEST-NET-3
        ("192.0.0.1", True),       # IETF protocol assignments
        # ── Multicast / Reserved ─────────────────────────────
        ("224.0.0.1", True),       # Multicast start
        ("239.255.255.255", True), # Multicast end
        ("240.0.0.1", True),       # Reserved
        ("255.255.255.255", True), # Broadcast
        # ── "This network" ───────────────────────────────────
        ("0.0.0.1", True),
        # ── IPv6 loopback ─────────────────────────────────────
        ("::1", True),
        # ── IPv6 unique local (fc00::/7) ──────────────────────
        ("fc00::1", True),
        ("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", True),
        # ── IPv6 link-local (fe80::/10) ───────────────────────
        ("fe80::1", True),
        ("feb0::1", True),
        # ── Public IPs — must NOT be blocked ─────────────────
        ("8.8.8.8", False),
        ("1.1.1.1", False),
        ("142.250.80.46", False),  # google.com
        ("104.16.132.229", False), # cloudflare
        ("2606:4700:4700::1111", False),  # Cloudflare DNS (public IPv6)
    ],
)
def test_is_private_or_reserved(addr: str, should_block: bool):
    result = _is_private_or_reserved(addr)
    assert result == should_block, (
        f"_is_private_or_reserved({addr!r}) returned {result}, expected {should_block}"
    )
