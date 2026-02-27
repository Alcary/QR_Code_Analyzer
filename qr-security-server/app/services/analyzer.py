"""
URL Analyzer — Multi-Layer Orchestrator (v3)

Analysis pipeline:
1. Input validation & URL normalization
2. Cache check (TTL-based)
3. ML prediction (XGBoost on 95 URL features)
4. Parallel network checks (DNS, SSL, HTTP, WHOIS)
5. Computed domain trust score (replaces static whitelist dampening)
6. Heuristic risk factors (URL-derived + network-derived)
7. Risk score computation combining all three signal layers
8. SHAP feature-attribution explanations
9. Final verdict: safe / suspicious / danger

"""

import asyncio
import logging
import time
from urllib.parse import urlparse

from cachetools import TTLCache

from app.services.ml.predictor import predictor
from app.services.url_features import get_risk_factors
from app.services.domain_reputation import (
    compute_domain_trust,
    get_registered_domain,
    get_full_domain,
    normalize_hostname,
    ReputationTier,
    KNOWN_SHORTENERS,
)
from app.services.network_inspector import network_inspector

logger = logging.getLogger(__name__)


class URLAnalyzer:
    """
    Combines ML predictions, computed domain trust, and network intelligence
    into a final security verdict with SHAP explanations.
    """

    # Thresholds for final risk score
    DANGER_THRESHOLD = 0.70
    SUSPICIOUS_THRESHOLD = 0.40

    def __init__(self, cache_maxsize: int = 2000, cache_ttl: int = 3600):
        self.cache: TTLCache = TTLCache(maxsize=cache_maxsize, ttl=cache_ttl)

    # ──────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────

    async def analyze(self, url: str) -> dict:
        """
        Full URL analysis. Returns dict with:
          status, message, risk_score, details
        """
        start = time.perf_counter()

        # ── 1. Cache ──
        if url in self.cache:
            logger.info("Cache hit: %s", url)
            return self.cache[url]

        # ── 2. Parse ──
        try:
            parsed = urlparse(url if "://" in url else f"https://{url}")
            scheme = parsed.scheme.lower()
        except Exception:
            return self._result("danger", "Invalid URL format", risk_score=1.0)

        if scheme not in ("http", "https"):
            return self._result("suspicious", "Non-standard protocol", risk_score=0.5)

        hostname = normalize_hostname(url)
        if not hostname:
            return self._result("danger", "Invalid or empty hostname", risk_score=1.0)
        registered_domain = get_registered_domain(hostname)
        full_domain = get_full_domain(hostname)
        path = parsed.path

        # ── 3. ML Prediction (XGBoost) ──
        # Run CPU-bound XGBoost inference in a thread to avoid blocking
        # the async event loop.
        loop = asyncio.get_running_loop()
        try:
            ml_result = await loop.run_in_executor(None, predictor.predict, url)
        except Exception as e:
            logger.error("ML predictor raised an exception: %s", e)
            ml_result = None
        if ml_result:
            ml_score = ml_result["ml_score"]
            xgb_score = ml_result["xgb_score"]
            explanation = ml_result.get("explanation")
        else:
            ml_score = 0.5
            xgb_score = 0.5
            explanation = None
            logger.warning("ML model not loaded or failed, using fallback score")

        # ── 4. Network Checks (parallel) ──
        net = await network_inspector.inspect_all(url, hostname, registered_domain)

        # ── 5. Computed Domain Trust (replaces static whitelist) ──
        reputation = compute_domain_trust(
            hostname=hostname,
            url_path=path,
            whois_age_days=net.whois.age_days,
            ssl_valid=net.ssl.valid,
            ssl_cert_age_days=net.ssl.cert_age_days,
            ssl_days_until_expiry=net.ssl.days_until_expiry,
            ssl_error=net.ssl.error,
            dns_resolved=net.dns.resolved,
            dns_ttl=net.dns.ttl,
            dns_flags=net.dns.flags,
        )
        dampened_ml = ml_score * reputation.dampening_factor

        logger.info(
            "ML=%.3f (xgb=%.3f) × trust_dampen=%.2f → %.3f  [%s / %s]",
            ml_score, xgb_score,
            reputation.dampening_factor, dampened_ml,
            reputation.tier.value, registered_domain,
        )

        # ── 6. Network Risk Signals ──
        network_risk, network_factors = self._compute_network_risk(net, reputation.tier, registered_domain)

        # ── 7. Heuristic Risk Factors ──
        risk_factors = get_risk_factors(url)
        risk_factors.extend(network_factors)
        heuristic_risk = self._compute_heuristic_risk(risk_factors)

        # ── 8. Final Score ──
        # Three signals, each capturing different risk dimensions:
        #   - dampened_ml    : ML model score adjusted by domain trust
        #   - network_risk   : observable network anomalies (SSL, DNS, HTTP, WHOIS)
        #   - heuristic_risk : URL-derived risk factors (keywords, structure)
        #
        # The heuristic component ensures risk factors displayed in the
        # UI actually influence the final risk percentage.
        final_score = 0.55 * dampened_ml + 0.25 * network_risk + 0.20 * heuristic_risk
        final_score = max(0.0, min(1.0, final_score))

        # ── 9. Hard overrides & verdict ──
        status, message = self._decide(
            final_score=final_score,
            net=net,
            reputation=reputation,
            risk_factors=risk_factors,
        )

        elapsed_ms = int((time.perf_counter() - start) * 1000)

        result = self._result(
            status=status,
            message=message,
            risk_score=round(final_score, 4),
            details={
                "ml": {
                    "ml_score": round(ml_score, 4),
                    "xgb_score": round(xgb_score, 4),
                    "dampened_score": round(dampened_ml, 4),
                    "explanation": self._format_explanation(explanation),
                },
                "domain": {
                    "registered_domain": registered_domain,
                    "full_domain": full_domain,
                    "reputation_tier": reputation.tier.value,
                    "dampening_factor": reputation.dampening_factor,
                    "trust_description": reputation.description,
                    "age_days": net.whois.age_days,
                    "registrar": net.whois.registrar,
                },
                "network": {
                    "dns_resolved": net.dns.resolved,
                    "dns_ttl": net.dns.ttl,
                    "dns_flags": net.dns.flags,
                    "ssl_valid": net.ssl.valid,
                    "ssl_issuer": net.ssl.issuer,
                    "ssl_days_until_expiry": net.ssl.days_until_expiry,
                    "ssl_is_new_cert": net.ssl.is_new_cert,
                    "http_status": net.http.status_code,
                    "redirect_count": net.http.redirect_count,
                    "final_url": net.http.final_url,
                    "content_flags": net.http.content_flags,
                },
                "risk_factors": risk_factors if risk_factors else [],
                "analysis_time_ms": elapsed_ms,
            },
        )

        self.cache[url] = result
        return result

    # ──────────────────────────────────────────────────────────
    # Network Risk Scoring
    # ──────────────────────────────────────────────────────────

    def _compute_network_risk(self, net, tier: ReputationTier, registered_domain: str = "") -> tuple[float, list[dict]]:
        """
        Compute a 0.0–1.0 risk score from network signals.
        Returns (score, list_of_risk_factor_dicts).
        """
        risk = 0.0
        factors: list[dict] = []

        def _rf(code: str, message: str, severity: str, evidence: str | None = None) -> dict:
            f: dict = {"code": code, "message": message, "severity": severity}
            if evidence is not None:
                f["evidence"] = evidence
            return f

        # DNS flags
        if "very_low_ttl" in net.dns.flags:
            risk += 0.10
            factors.append(_rf("very_low_ttl", "Very low DNS TTL (fast-flux indicator)", "high"))
        if "no_mx_records" in net.dns.flags:
            risk += 0.02
            factors.append(_rf("no_mx_records", "No MX records", "low"))
        if "suspicious_nameserver" in net.dns.flags:
            risk += 0.10
            factors.append(_rf("suspicious_nameserver", "Suspicious nameserver provider", "high"))

        # SSL
        if net.ssl.error == "ssl_verification_failed":
            risk += 0.20
            factors.append(_rf("ssl_invalid_cert", "SSL certificate verification failed", "high"))
        elif net.ssl.is_new_cert:
            risk += 0.10
            factors.append(_rf(
                "ssl_new_cert",
                f"SSL certificate is very new ({net.ssl.cert_age_days}d)",
                "medium",
                evidence=str(net.ssl.cert_age_days),
            ))
        if not net.ssl.valid and net.ssl.error not in ("ssl_connection_failed", "ssl_verification_failed"):
            risk += 0.05

        # HTTP
        if net.http.redirect_count > 3:
            risk += 0.10
            factors.append(_rf(
                "excessive_redirects",
                f"Excessive redirects ({net.http.redirect_count})",
                "medium",
                evidence=str(net.http.redirect_count),
            ))
        is_shortener = registered_domain in KNOWN_SHORTENERS
        if net.http.redirect_domain_mismatch and not is_shortener:
            risk += 0.15
            factors.append(_rf("cross_domain_redirect", "Redirects to different domain", "high"))
        if net.http.scheme_warning:
            risk += 0.08
            factors.append(_rf("no_https", "No HTTPS encryption", "medium"))

        _content_map = {
            "password_field":      (0.10, "page_password_field",   "Page contains password field",        "high"),
            "billing_info_request":(0.15, "page_billing_info",     "Page requests billing information",   "high"),
            "sensitive_id_request":(0.15, "page_sensitive_id",     "Page requests sensitive ID",          "high"),
            "geolocation_tracking":(0.10, "page_geolocation",      "Page tracks geolocation",             "medium"),
            "obfuscated_javascript":(0.15,"page_obfuscated_js",    "Obfuscated JavaScript detected",      "high"),
            "excessive_iframes":   (0.10, "page_excessive_iframes","Excessive iframes (click-jacking risk)","medium"),
        }
        for flag in net.http.content_flags:
            if flag in _content_map:
                weight, code, message, severity = _content_map[flag]
                risk += weight
                factors.append(_rf(code, message, severity))

        # WHOIS
        if net.whois.is_new_domain:
            risk += 0.15
            factors.append(_rf(
                "new_domain",
                f"Domain registered recently ({net.whois.age_days}d ago)",
                "high",
                evidence=str(net.whois.age_days),
            ))

        return min(1.0, risk), factors

    # ──────────────────────────────────────────────────────────
    # Heuristic Risk Scoring
    # ──────────────────────────────────────────────────────────

    # Severity → score contribution per factor.
    # Replaces the previous fragile substring-matching approach: any rename
    # of a factor message would silently break scoring. Codes are stable.
    _SEVERITY_WEIGHTS: dict[str, float] = {
        "critical": 0.20,
        "high":     0.12,
        "medium":   0.06,
        "low":      0.03,
    }

    def _compute_heuristic_risk(self, risk_factors: list[dict]) -> float:
        """
        Convert structured risk factors into a 0.0–1.0 risk score.

        Each factor contributes according to its ``severity`` field.
        Capped at 1.0.
        """
        if not risk_factors:
            return 0.0
        risk = sum(
            self._SEVERITY_WEIGHTS.get(f.get("severity", "low"), 0.03)
            for f in risk_factors
        )
        return min(1.0, risk)

    # ──────────────────────────────────────────────────────────
    # SHAP Explanation Formatting
    # ──────────────────────────────────────────────────────────

    @staticmethod
    def _format_explanation(explanation: dict | None) -> list[dict] | None:
        """Format SHAP explanation for the API response."""
        if explanation is None:
            return None
        return explanation.get("contributions", [])

    # ──────────────────────────────────────────────────────────
    # Decision Logic
    # ──────────────────────────────────────────────────────────

    def _decide(
        self,
        final_score: float,
        net,
        reputation,
        risk_factors: list[dict],
    ) -> tuple[str, str]:
        """Return (status, message) based on all signals."""

        # Hard override: DNS failure = domain doesn't exist
        if net.dns.error == "domain_not_found":
            return "danger", "Domain does not exist (DNS failure)"

        # Hard override: SSRF attempt — URL targeted internal/private network
        if net.http.error in ("ssrf_blocked", "ssrf_check_failed"):
            return "danger", "SSRF attempt blocked — URL targets internal network"

        # Hard override: actual server error (5xx range only)
        # Non-standard codes like 999 (LinkedIn anti-bot) are not server errors
        if net.http.status_code and 500 <= net.http.status_code < 600:
            return "danger", f"Server error ({net.http.status_code})"

        # Combined failure: unreachable + DNS failed
        if net.http.error in ("site_unreachable", "timeout") and not net.dns.resolved:
            return "danger", "Site is unreachable and DNS failed"

        # Score-based
        if final_score >= self.DANGER_THRESHOLD:
            top = ", ".join(f["message"] for f in risk_factors[:3]) if risk_factors else "multiple signals"
            return "danger", f"High risk detected ({final_score:.0%}): {top}"

        if final_score >= self.SUSPICIOUS_THRESHOLD:
            top = ", ".join(f["message"] for f in risk_factors[:2]) if risk_factors else "elevated risk"
            return "suspicious", f"Suspicious patterns ({final_score:.0%}): {top}"

        # Safe — add context from trust tier
        tier = reputation.tier
        if tier == ReputationTier.TRUSTED:
            return "safe", "Verified safe — established domain"
        if tier == ReputationTier.MODERATE:
            return "safe", "No threats detected — moderate trust"
        if tier == ReputationTier.UNTRUSTED:
            return "safe", "Shortened URL — destination verified safe"

        return "safe", "No threats detected"

    # ──────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────

    @staticmethod
    def _result(status: str, message: str, risk_score: float = 0.0, details: dict | None = None) -> dict:
        return {
            "status": status,
            "message": message,
            "risk_score": risk_score,
            "details": details,
        }


# Singleton
analyzer = URLAnalyzer()
