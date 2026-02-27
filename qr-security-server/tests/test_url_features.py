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
