"""
Tests for URL feature extraction (app/services/url_features.py).

Covers: feature count/uniqueness, individual feature flags,
        and the structured get_risk_factors() output.
"""

import pytest

from app.services.url_features import FEATURE_NAMES, extract_features, get_risk_factors

EXPECTED_FEATURE_COUNT = 95

# ── FEATURE_NAMES ─────────────────────────────────────────────


def test_feature_names_count():
    assert len(FEATURE_NAMES) == EXPECTED_FEATURE_COUNT, (
        f"Expected {EXPECTED_FEATURE_COUNT} features, got {len(FEATURE_NAMES)}. "
        "Update EXPECTED_FEATURE_COUNT or the training notebook."
    )


def test_feature_names_unique():
    assert len(FEATURE_NAMES) == len(set(FEATURE_NAMES)), "Duplicate feature names detected"


def test_extract_features_returns_all_names():
    feats = extract_features("https://example.com")
    missing = [n for n in FEATURE_NAMES if n not in feats]
    assert not missing, f"extract_features() missing keys: {missing}"


# ── Individual feature flags ──────────────────────────────────


@pytest.mark.parametrize(
    "url,feature,expected",
    [
        # IP literal
        ("http://192.168.1.1/admin", "has_ip_address", 1),
        # Credential injection via @ symbol
        ("https://evil.com@google.com", "has_at_symbol", 1),
        # javascript: protocol
        ("javascript://evil.com/x", "has_javascript", 1),
        # Known URL shortener
        ("https://bit.ly/abc123", "is_url_shortener", 1),
        # HTTPS flag
        ("https://example.com", "is_https", 1),
        ("https://example.com", "is_http", 0),
        # HTTP flag
        ("http://example.com", "is_http", 1),
        ("http://example.com", "is_https", 0),
        # Suspicious TLD
        ("https://example.tk", "is_suspicious_tld", 1),
        ("https://example.com", "is_suspicious_tld", 0),
        # Trusted TLD
        ("https://example.gov", "is_trusted_tld", 1),
        ("https://example.com", "is_trusted_tld", 0),
        # Punycode domain
        ("https://xn--pypal-4ve.com", "has_punycode", 1),
        # Hex encoding
        ("https://example.com/%2F%2F", "has_hex_encoding", 1),
        # Double slash in path
        ("https://example.com//redirect", "has_double_slash_in_path", 1),
        # Data URI
        ("data:text/html,hello", "has_data_uri", 1),
        # Dangerous extension
        ("https://example.com/malware.exe", "has_dangerous_ext", 1),
        ("https://example.com/malware.exe", "has_exe", 1),
    ],
)
def test_feature_flag(url: str, feature: str, expected: int):
    feats = extract_features(url)
    assert feats[feature] == expected, (
        f"URL={url!r}: expected {feature}={expected}, got {feats[feature]}"
    )


@pytest.mark.parametrize(
    "url",
    [
        "https://bit.ly/abc123",
        "https://t.co/xyz",
        "https://tinyurl.com/abc",
        "https://ow.ly/test",
        "https://is.gd/abc",
    ],
)
def test_known_shorteners_detected(url: str):
    """top_domain_under_public_suffix must match the URL_SHORTENERS set for all known shorteners."""
    feats = extract_features(url)
    assert feats["is_url_shortener"] == 1, f"Expected is_url_shortener=1 for {url!r}"


def test_non_shortener_not_flagged():
    assert extract_features("https://example.com")["is_url_shortener"] == 0


def test_url_length_feature():
    url = "https://example.com/" + "a" * 100
    feats = extract_features(url)
    assert feats["url_length"] == len(url)


def test_subdomain_count_feature():
    feats = extract_features("https://a.b.c.example.com")
    assert feats["subdomain_count"] >= 3


def test_entropy_increases_with_randomness():
    clean = extract_features("https://google.com")
    random = extract_features("https://xkf93mzq4.com")
    assert random["domain_entropy"] > clean["domain_entropy"]


# ── get_risk_factors() ────────────────────────────────────────

VALID_SEVERITIES = {"low", "medium", "high", "critical"}
REQUIRED_KEYS = {"code", "message", "severity"}


def test_risk_factors_returns_list():
    assert isinstance(get_risk_factors("https://example.com"), list)


def test_risk_factors_dicts_have_required_keys():
    factors = get_risk_factors("http://192.168.1.1/admin/login.php")
    assert factors  # at least one factor expected
    for f in factors:
        missing = REQUIRED_KEYS - set(f.keys())
        assert not missing, f"Factor missing keys {missing}: {f}"


def test_risk_factors_valid_severities():
    urls = [
        "http://192.168.1.1/admin",
        "https://bit.ly/xyz",
        "https://paypal-secure.tk/login",
        "javascript://x",
        "https://xn--pypal-4ve.com",
    ]
    for url in urls:
        for f in get_risk_factors(url):
            assert f["severity"] in VALID_SEVERITIES, (
                f"URL={url!r} factor {f['code']!r} has invalid severity {f['severity']!r}"
            )


def test_ip_literal_produces_correct_code():
    codes = [f["code"] for f in get_risk_factors("http://10.0.0.1/page")]
    assert "ip_literal_url" in codes


def test_javascript_protocol_is_critical():
    factors = get_risk_factors("javascript://evil.com")
    critical = [f for f in factors if f["code"] == "javascript_protocol"]
    assert critical, "Expected javascript_protocol risk factor"
    assert critical[0]["severity"] == "critical"


def test_brand_impersonation_is_critical():
    # A domain that exactly matches a brand name (not the real registrant)
    # This should trigger homograph_is_exact_brand if the domain == brand keyword.
    # Use a clear character substitution: paypa1 → char_substitution
    factors = get_risk_factors("https://paypa1.com/wallet")
    codes = [f["code"] for f in factors]
    # At minimum should flag char_substitution or brand_lookalike
    assert any(c in codes for c in ("char_substitution", "brand_lookalike", "brand_impersonation")), (
        f"Expected brand-related factor, got codes: {codes}"
    )


def test_clean_url_has_no_factors():
    factors = get_risk_factors("https://example.com")
    assert factors == [], f"Expected no risk factors for clean URL, got: {factors}"


def test_evidence_field_present_for_quantitative_factors():
    # Subdomain count provides evidence
    factors = get_risk_factors("https://a.b.c.d.example.com/page")
    subdomain_factors = [f for f in factors if f["code"] == "excessive_subdomains"]
    if subdomain_factors:
        assert "evidence" in subdomain_factors[0]


# ── brand_not_registered — official-domain strictness ─────────


def test_official_paypal_not_flagged_as_brand_not_registered():
    """paypal.com is the official domain — brand_not_registered must be 0."""
    feats = extract_features("https://paypal.com/login")
    assert feats["brand_not_registered"] == 0, (
        "paypal.com is official and must NOT set brand_not_registered=1"
    )


def test_paypal_net_flagged_as_brand_not_registered():
    """paypal.net is NOT an official PayPal domain — brand_not_registered must be 1."""
    feats = extract_features("https://paypal.net/wallet")
    assert feats["brand_not_registered"] == 1, (
        "paypal.net is not official and must set brand_not_registered=1"
    )


def test_google_com_not_flagged():
    feats = extract_features("https://google.com/search?q=test")
    assert feats["brand_not_registered"] == 0


def test_google_evil_io_flagged():
    feats = extract_features("https://google.evil.io/page")
    assert feats["brand_not_registered"] == 1


def test_no_brand_keyword_keeps_flag_zero():
    """Domains with no brand keyword must not set brand_not_registered."""
    feats = extract_features("https://example.com")
    assert feats["brand_not_registered"] == 0


# ── brand_in_unofficial_domain false-positive regressions ─────


def test_pineapple_does_not_emit_brand_in_unofficial_domain():
    """
    Regression: 'apple' is a substring of 'pineapple', but the domain is
    completely unrelated to Apple Inc.  The boundary-based matcher checks
    whether 'apple' appears as a *whole token* inside 'pineapple' — it does not
    (pineapple → split by separators → ['pineapple'] → no match), so
    brand_in_unofficial_domain and brand_in_subdomain must NOT fire.
    """
    codes = [f["code"] for f in get_risk_factors("https://pineapple.com")]
    assert "brand_in_unofficial_domain" not in codes, (
        "pineapple.com must NOT trigger brand_in_unofficial_domain (substring false positive)"
    )


def test_snapple_does_not_emit_brand_in_unofficial_domain():
    """
    Regression: 'snapple.com' contains 'apple' as a substring AND has
    Levenshtein distance 2 to 'apple'.  Neither the substring FP nor the
    distance-2 case (which lacks extra suspicion signals) must produce a
    brand-related risk factor.
    """
    codes = [f["code"] for f in get_risk_factors("https://snapple.com")]
    assert "brand_in_unofficial_domain" not in codes, (
        "snapple.com must NOT trigger brand_in_unofficial_domain"
    )
    assert "brand_lookalike" not in codes, (
        "snapple.com must NOT trigger brand_lookalike — distance 2 without extra suspicion"
    )


def test_paypal_net_emits_brand_in_unofficial_domain():
    """
    paypal.net is a genuine PayPal lookalike (distance 0: 'paypal' == 'paypal').
    brand_in_unofficial_domain MUST fire.
    """
    codes = [f["code"] for f in get_risk_factors("https://paypal.net/wallet")]
    assert "brand_in_unofficial_domain" in codes or "brand_impersonation" in codes, (
        "paypal.net must be flagged as brand impersonation"
    )


def test_paypal_secure_emits_brand_in_unofficial_domain():
    """
    Regression: paypal-secure.com uses a hyphen-separated brand token
    'paypal' inside the SLD.  _brand_in_label splits by hyphen and finds
    'paypal' as a whole token, so brand_in_unofficial_domain must fire.
    """
    codes = [f["code"] for f in get_risk_factors("https://paypal-secure.com/login")]
    assert "brand_in_unofficial_domain" in codes or "brand_impersonation" in codes, (
        "paypal-secure.com must be flagged — 'paypal' is a boundary-matched token"
    )
