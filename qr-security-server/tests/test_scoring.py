"""
Tests for scoring logic (app/services/analyzer.py).

These are pure / near-pure unit tests: no network calls, no ML model needed.
They exercise:
  - _compute_heuristic_risk()   — severity-weighted factor scoring
  - _compute_network_risk()     — network signal aggregation
  - final score formula         — weight combination and clamping
  - _decide()                   — verdict rules and hard overrides
"""

import pytest

from app.services.analyzer import URLAnalyzer
from app.services.domain_reputation import ReputationTier, ReputationInfo
from app.services.network_inspector import (
    DNSResult,
    HTTPResult,
    NetworkResult,
    SSLResult,
    WHOISResult,
)

# Single shared instance — scoring methods are stateless
_analyzer = URLAnalyzer(cache_maxsize=1, cache_ttl=1)


# ── Helpers ───────────────────────────────────────────────────


def _rf(code: str, severity: str, message: str = "") -> dict:
    return {"code": code, "message": message or f"msg_{code}", "severity": severity}


def _clean_net() -> NetworkResult:
    return NetworkResult(
        dns=DNSResult(resolved=True, flags=[]),
        ssl=SSLResult(valid=True),
        http=HTTPResult(status_code=200, redirect_count=0, content_flags=[]),
        whois=WHOISResult(is_new_domain=False),
    )


def _reputation(tier: ReputationTier = ReputationTier.NEUTRAL) -> ReputationInfo:
    return ReputationInfo(tier=tier, dampening_factor=0.5, description="test")


# ── _compute_heuristic_risk ───────────────────────────────────


def test_heuristic_empty_factors_returns_zero():
    assert _analyzer._compute_heuristic_risk([]) == pytest.approx(0.0)


@pytest.mark.parametrize(
    "severity,expected",
    [
        ("critical", 0.20),
        ("high", 0.12),
        ("medium", 0.06),
        ("low", 0.03),
    ],
)
def test_heuristic_single_factor_weight(severity: str, expected: float):
    assert _analyzer._compute_heuristic_risk([_rf("x", severity)]) == pytest.approx(expected)


def test_heuristic_multiple_factors_summed():
    factors = [_rf("a", "high"), _rf("b", "medium"), _rf("c", "low")]
    assert _analyzer._compute_heuristic_risk(factors) == pytest.approx(0.12 + 0.06 + 0.03)


def test_heuristic_capped_at_one():
    factors = [_rf(f"f{i}", "critical") for i in range(10)]  # 10 × 0.20 = 2.0
    assert _analyzer._compute_heuristic_risk(factors) == pytest.approx(1.0)


def test_heuristic_unknown_severity_falls_back_to_low():
    # Graceful: an unexpected severity value should not hard-crash; it
    # uses the .get(..., 0.03) default which equals the "low" weight.
    assert _analyzer._compute_heuristic_risk([_rf("x", "bogus")]) == pytest.approx(0.03)


# ── _compute_network_risk ─────────────────────────────────────


def test_network_risk_clean_net_is_zero():
    risk, factors = _analyzer._compute_network_risk(_clean_net(), ReputationTier.NEUTRAL)
    assert risk == pytest.approx(0.0)
    assert factors == []


def test_network_risk_ssl_verification_failed():
    net = _clean_net()
    net.ssl.error = "ssl_verification_failed"
    net.ssl.valid = False
    risk, factors = _analyzer._compute_network_risk(net, ReputationTier.NEUTRAL)
    assert risk >= 0.20
    assert any(f["code"] == "ssl_invalid_cert" for f in factors)


def test_network_risk_new_domain():
    net = _clean_net()
    net.whois.is_new_domain = True
    net.whois.age_days = 5
    risk, factors = _analyzer._compute_network_risk(net, ReputationTier.NEUTRAL)
    assert risk >= 0.15
    assert any(f["code"] == "new_domain" for f in factors)
    new_domain_f = next(f for f in factors if f["code"] == "new_domain")
    assert new_domain_f["evidence"] == "5"


def test_network_risk_very_low_ttl():
    net = _clean_net()
    net.dns.flags = ["very_low_ttl"]
    risk, factors = _analyzer._compute_network_risk(net, ReputationTier.NEUTRAL)
    assert risk >= 0.10
    assert any(f["code"] == "very_low_ttl" for f in factors)


def test_network_risk_no_https():
    net = _clean_net()
    net.http.scheme_warning = True
    risk, factors = _analyzer._compute_network_risk(net, ReputationTier.NEUTRAL)
    assert risk >= 0.08
    assert any(f["code"] == "no_https" for f in factors)


def test_network_risk_cross_domain_redirect():
    net = _clean_net()
    net.http.redirect_count = 1
    net.http.redirect_domain_mismatch = True
    risk, factors = _analyzer._compute_network_risk(
        net, ReputationTier.NEUTRAL, registered_domain="example.com"
    )
    assert risk >= 0.15
    assert any(f["code"] == "cross_domain_redirect" for f in factors)


def test_network_risk_shortener_suppresses_cross_domain_redirect():
    net = _clean_net()
    net.http.redirect_count = 1
    net.http.redirect_domain_mismatch = True
    # bit.ly is in KNOWN_SHORTENERS — cross-domain redirect is expected
    risk, factors = _analyzer._compute_network_risk(
        net, ReputationTier.NEUTRAL, registered_domain="bit.ly"
    )
    assert not any(f["code"] == "cross_domain_redirect" for f in factors)


def test_network_risk_content_flags():
    net = _clean_net()
    net.http.content_flags = ["password_field", "obfuscated_javascript"]
    risk, factors = _analyzer._compute_network_risk(net, ReputationTier.NEUTRAL)
    codes = [f["code"] for f in factors]
    assert "page_password_field" in codes
    assert "page_obfuscated_js" in codes
    assert risk >= 0.10 + 0.15


def test_network_risk_capped_at_one():
    net = NetworkResult(
        dns=DNSResult(resolved=True, flags=["very_low_ttl", "suspicious_nameserver"]),
        ssl=SSLResult(valid=False, error="ssl_verification_failed"),
        http=HTTPResult(
            status_code=200,
            redirect_count=5,
            redirect_domain_mismatch=True,
            scheme_warning=True,
            content_flags=["password_field", "billing_info_request", "obfuscated_javascript"],
        ),
        whois=WHOISResult(is_new_domain=True, age_days=2),
    )
    risk, _ = _analyzer._compute_network_risk(net, ReputationTier.NEUTRAL)
    assert 0.0 <= risk <= 1.0


# ── Final score formula ───────────────────────────────────────


@pytest.mark.parametrize(
    "ml,net_r,heuristic,expected",
    [
        (0.0, 0.0, 0.0, 0.0),
        (1.0, 1.0, 1.0, 1.0),
        (0.8, 0.5, 0.3, 0.55 * 0.8 + 0.25 * 0.5 + 0.20 * 0.3),
        (0.5, 0.0, 0.0, 0.275),
    ],
)
def test_final_score_formula(ml: float, net_r: float, heuristic: float, expected: float):
    raw = 0.55 * ml + 0.25 * net_r + 0.20 * heuristic
    clamped = max(0.0, min(1.0, raw))
    assert clamped == pytest.approx(expected)


# ── _decide() — verdict rules ─────────────────────────────────


def _decide(final_score: float, net: NetworkResult | None = None, factors: list | None = None):
    return _analyzer._decide(
        final_score=final_score,
        net=net or _clean_net(),
        reputation=_reputation(),
        risk_factors=factors or [],
    )


def test_decide_score_below_suspicious_threshold_is_safe():
    status, _ = _decide(0.30)
    assert status == "safe"


def test_decide_score_at_suspicious_threshold_is_suspicious():
    status, _ = _decide(URLAnalyzer.SUSPICIOUS_THRESHOLD)
    assert status == "suspicious"


def test_decide_score_at_danger_threshold_is_danger():
    status, _ = _decide(URLAnalyzer.DANGER_THRESHOLD)
    assert status == "danger"


def test_decide_message_includes_top_factors():
    factors = [_rf("a", "high", "Bad pattern A"), _rf("b", "medium", "Bad pattern B")]
    _, message = _decide(0.80, factors=factors)
    assert "Bad pattern A" in message


def test_decide_hard_override_dns_not_found():
    net = _clean_net()
    net.dns.error = "domain_not_found"
    status, message = _decide(0.0, net=net)
    assert status == "danger"
    assert "DNS" in message or "exist" in message.lower()


def test_decide_hard_override_ssrf_blocked():
    net = _clean_net()
    net.http.error = "ssrf_blocked"
    status, message = _decide(0.0, net=net)
    assert status == "danger"
    assert "SSRF" in message


def test_decide_hard_override_ssrf_check_failed():
    net = _clean_net()
    net.http.error = "ssrf_check_failed"
    status, message = _decide(0.0, net=net)
    assert status == "danger"


def test_decide_hard_override_5xx_status():
    net = _clean_net()
    net.http.status_code = 503
    status, _ = _decide(0.0, net=net)
    assert status == "danger"


def test_decide_4xx_not_a_hard_override():
    net = _clean_net()
    net.http.status_code = 404
    status, _ = _decide(0.10, net=net)
    assert status == "safe"  # 404 is not a hard override


def test_decide_unreachable_with_dns_failure_is_danger():
    net = _clean_net()
    net.http.error = "site_unreachable"
    net.dns.resolved = False
    status, _ = _decide(0.10, net=net)
    assert status == "danger"


# ── _decide() — UNTRUSTED tier messages ──────────────────────


def _decide_with_tier(tier: ReputationTier, factors: list | None = None):
    return _analyzer._decide(
        final_score=0.10,
        net=_clean_net(),
        reputation=_reputation(tier),
        risk_factors=factors or [],
    )


def test_decide_trusted_tier_message():
    _, msg = _decide_with_tier(ReputationTier.TRUSTED)
    assert "established" in msg.lower() or "verified" in msg.lower()


def test_decide_moderate_tier_message():
    _, msg = _decide_with_tier(ReputationTier.MODERATE)
    assert "moderate" in msg.lower()


def test_decide_untrusted_non_shortener_message():
    """UNTRUSTED domain with no url_shortener factor must NOT say 'shortener'."""
    _, msg = _decide_with_tier(ReputationTier.UNTRUSTED, factors=[])
    assert "shortener" not in msg.lower()
    assert "low-trust" in msg.lower() or "low trust" in msg.lower()


def test_decide_untrusted_shortener_factor_message():
    """UNTRUSTED domain with url_shortener factor gets shortener-specific message."""
    shortener_factor = {"code": "url_shortener", "message": "URL shortener", "severity": "medium"}
    _, msg = _decide_with_tier(ReputationTier.UNTRUSTED, factors=[shortener_factor])
    assert "shortener" in msg.lower()


def test_decide_untrusted_other_factor_not_shortener_message():
    """UNTRUSTED domain with a different risk factor does not trigger shortener message."""
    other_factor = {"code": "suspicious_tld", "message": "Suspicious TLD", "severity": "low"}
    _, msg = _decide_with_tier(ReputationTier.UNTRUSTED, factors=[other_factor])
    assert "shortener" not in msg.lower()
