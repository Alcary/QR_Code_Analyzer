"""
Tests for homograph / typosquatting detection (app/services/homograph_detector.py).

Focus: boundary-based brand matching must not fire on arbitrary substrings.
"""

import pytest

from app.services.homograph_detector import (
    _brand_in_label,
    _hostname_has_brand,
    detect_char_substitution,
    extract_homograph_features,
    normalize_confusables,
)


# ── _brand_in_label (unit) ────────────────────────────────────


@pytest.mark.parametrize(
    "label,brand,expected",
    [
        # Exact label
        ("apple", "apple", True),
        ("paypal", "paypal", True),
        # Hyphen-separated tokens
        ("secure-apple", "apple", True),
        ("apple-login", "apple", True),
        ("paypal-login", "paypal", True),
        ("login-paypal", "paypal", True),
        # Underscore-separated tokens
        ("apple_secure", "apple", True),
        ("secure_apple", "apple", True),
        # brand + digits  (still impersonation)
        ("apple2", "apple", True),
        ("apple123", "apple", True),
        # digits + brand  (still impersonation)
        ("2apple", "apple", True),
        ("123apple", "apple", True),
        # Must NOT match embedded substrings
        ("pineapple", "apple", False),
        ("snapple", "apple", False),
        ("happlepay", "apple", False),
        ("paypalicious", "paypal", False),
        ("notpaypal", "paypal", False),
        # Unrelated label
        ("google", "apple", False),
        ("example", "paypal", False),
    ],
)
def test_brand_in_label(label: str, brand: str, expected: bool):
    assert _brand_in_label(label, brand) == expected, (
        f"_brand_in_label({label!r}, {brand!r}) should be {expected}"
    )


# ── _hostname_has_brand (unit) ────────────────────────────────


@pytest.mark.parametrize(
    "hostname,brand,expected",
    [
        # Full-label matches
        ("apple.com", "apple", True),
        ("secure-apple.com", "apple", True),
        ("paypal-login.com", "paypal", True),
        ("login.paypal.fake.com", "paypal", True),
        ("www.apple.com", "apple", True),   # "apple" is a whole label → True
        # Embedded substring — must NOT match
        ("pineapple.com", "apple", False),
        ("snapple.com", "apple", False),
        ("notpaypal.com", "paypal", False),
        ("paypalicious.com", "paypal", False),
        # Brand in subdomain label
        ("apple.evildomain.com", "apple", True),
        # Brand NOT in hostname
        ("news.bbc.co.uk", "apple", False),
    ],
)
def test_hostname_has_brand(hostname: str, brand: str, expected: bool):
    assert _hostname_has_brand(hostname, brand) == expected, (
        f"_hostname_has_brand({hostname!r}, {brand!r}) should be {expected}"
    )


# ── extract_homograph_features — is_exact_brand ───────────────


def _exact_brand(domain: str) -> int:
    return extract_homograph_features(domain)["homograph_is_exact_brand"]


def test_pineapple_not_flagged_as_apple():
    """Core regression: pineapple.com must NOT match brand 'apple'."""
    assert _exact_brand("pineapple.com") == 0


def test_snapple_not_flagged_as_apple():
    assert _exact_brand("snapple.com") == 0


def test_notpaypal_not_flagged():
    assert _exact_brand("notpaypal.com") == 0


def test_paypalicious_not_flagged():
    assert _exact_brand("paypalicious.com") == 0


def test_apple_official_not_flagged():
    """Official brand domains must not trigger the impersonation flag."""
    assert _exact_brand("apple.com") == 0  # exempt — is_official_domain=True


def test_secure_apple_flagged():
    """secure-apple.com is brand impersonation — hyphen-separated token."""
    assert _exact_brand("secure-apple.com") == 1


def test_paypal_login_flagged():
    """paypal-login.com is brand impersonation — token match."""
    assert _exact_brand("paypal-login.com") == 1


def test_apple_fake_tld_flagged():
    """apple.evil.io — 'apple' is a whole label, not official domain."""
    assert _exact_brand("apple.evil.io") == 1


def test_login_paypal_subdomain_flagged():
    """login.paypal.fake.com — paypal is a whole label, not official domain."""
    assert _exact_brand("login.paypal.fake.com") == 1


# ── detect_char_substitution ──────────────────────────────────


def test_char_sub_g00gle():
    assert detect_char_substitution("g00gle.com") is True


def test_char_sub_paypa1():
    """paypa1 → paypal via confusable '1'→'l', but '1' in CONFUSABLES maps to 'l'."""
    # normalize_confusables("paypa1") → "paypal" which matches brand
    assert detect_char_substitution("paypa1.com") is True


def test_char_sub_amaz0n():
    assert detect_char_substitution("amaz0n.com") is True


def test_char_sub_real_google_not_flagged():
    """The real google.com is not a substitution attack."""
    assert detect_char_substitution("google.com") is False


def test_char_sub_pineapple_not_flagged():
    """pineapple has no confusable substitutions; must not be flagged."""
    assert detect_char_substitution("pineapple.com") is False

def test_paypal_net_not_official_flagged():
    assert _exact_brand("paypal.net") == 1

def test_paypal_official_not_flagged():
    assert _exact_brand("paypal.com") == 0

def test_char_sub_cyrillic_apple():
    """а (Cyrillic) in domain → confusable substitution for 'apple'."""
    # Use a domain where apple is a whole label after normalization
    cyrillic_a = "\u0430"  # Cyrillic а looks like Latin a
    domain = f"{cyrillic_a}pple-login.com"  # аpple-login.com → apple-login → token "apple"
    # normalize_confusables("аpple-login") → "apple-login", brand "apple" found via token
    assert detect_char_substitution(domain) is True


# ── normalize_confusables sanity ─────────────────────────────


def test_normalize_confusables_g00gle():
    assert normalize_confusables("g00gle") == "google"


def test_normalize_confusables_paypa1():
    assert normalize_confusables("paypa1") == "paypal"


def test_normalize_confusables_clean_unchanged():
    assert normalize_confusables("example") == "example"
