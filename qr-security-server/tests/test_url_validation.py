"""
Tests for ScanRequest URL validation (app/models/schemas.py).

Covers: scheme normalisation, max-length guard, netloc check,
whitespace stripping, and unsupported scheme rejection.
"""

import pytest
from pydantic import ValidationError

from app.models.schemas import ScanRequest


def _v(url: str) -> str:
    """Validate and return the normalised URL, or raise ValidationError."""
    return ScanRequest(url=url).url


# ── valid inputs ──────────────────────────────────────────────

def test_https_url_passes_unchanged():
    assert _v("https://example.com") == "https://example.com"


def test_http_url_passes_unchanged():
    assert _v("http://example.com/path") == "http://example.com/path"


def test_bare_domain_gets_https_prepended():
    assert _v("example.com") == "https://example.com"


def test_bare_domain_with_path_gets_https():
    assert _v("example.com/some/path?q=1") == "https://example.com/some/path?q=1"


def test_whitespace_is_stripped():
    assert _v("  https://example.com  ") == "https://example.com"


def test_query_string_preserved():
    url = "https://example.com/search?q=hello+world&lang=en"
    assert _v(url) == url


def test_fragment_preserved():
    url = "https://example.com/page#section"
    assert _v(url) == url


# ── invalid inputs ────────────────────────────────────────────

def test_ftp_scheme_rejected():
    with pytest.raises(ValidationError) as exc:
        _v("ftp://example.com")
    assert "Unsupported scheme" in str(exc.value)


def test_javascript_scheme_rejected():
    with pytest.raises(ValidationError) as exc:
        _v("javascript://evil.com")
    assert "Unsupported scheme" in str(exc.value)


def test_data_uri_rejected():
    with pytest.raises(ValidationError) as exc:
        _v("data:text/html,<script>alert(1)</script>")
    assert "Unsupported scheme" in str(exc.value)


def test_url_too_long_rejected():
    with pytest.raises(ValidationError):
        _v("https://example.com/" + "a" * 2100)


def test_empty_string_rejected():
    with pytest.raises(ValidationError):
        _v("")


def test_whitespace_only_rejected():
    # After stripping, the string is empty → min_length=1 triggers
    with pytest.raises(ValidationError):
        _v("   ")
