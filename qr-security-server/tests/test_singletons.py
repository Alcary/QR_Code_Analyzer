"""
Tests that application singletons are wired to application settings,
not to hardcoded defaults.
"""

from app.services.network_inspector import network_inspector
from app.core.config import settings


def test_network_inspector_http_timeout_matches_settings():
    """NetworkInspector singleton must use NETWORK_TIMEOUT from settings."""
    assert network_inspector.http_timeout == settings.NETWORK_TIMEOUT, (
        f"Expected http_timeout={settings.NETWORK_TIMEOUT}, "
        f"got {network_inspector.http_timeout}"
    )


def test_network_inspector_whois_timeout_matches_settings():
    """NetworkInspector singleton must use WHOIS_TIMEOUT from settings, not the 10.0 default."""
    assert network_inspector.whois_timeout == settings.WHOIS_TIMEOUT, (
        f"Expected whois_timeout={settings.WHOIS_TIMEOUT}, "
        f"got {network_inspector.whois_timeout}"
    )
