"""
URL Analyzer — Multi-Layer Orchestrator

Analysis pipeline:
1. Input validation & URL normalization
2. Cache check (TTL-based)
3. ML Ensemble prediction (XGBoost + DistilBERT)
4. Domain reputation lookup (4 tiers with dampening)
5. Parallel network checks (DNS, SSL, HTTP, WHOIS)
6. Risk score computation combining all signals
7. Final verdict: safe / suspicious / danger
"""

import logging
import time
from urllib.parse import urlparse

from cachetools import TTLCache

from app.services.ml.predictor import predictor
from app.services.url_features import get_risk_factors
from app.services.domain_reputation import (
    get_reputation,
    get_registered_domain,
    get_full_domain,
    normalize_hostname,
    ReputationTier,
)
from app.services.network_inspector import network_inspector

logger = logging.getLogger(__name__)


class URLAnalyzer:
    """
    Combines ML predictions, domain reputation, and network intelligence
    into a final security verdict.
    """

    # Thresholds for final risk score (tuned for calibrated probabilities)
    DANGER_THRESHOLD = 0.70
    SUSPICIOUS_THRESHOLD = 0.40

    # Weight split: ML vs network-derived signals
    ML_WEIGHT = 0.75
    NETWORK_WEIGHT = 0.25

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
            netloc = parsed.netloc.lower()
        except Exception:
            return self._result("danger", "Invalid URL format", risk_score=1.0)

        if scheme not in ("http", "https"):
            return self._result("suspicious", "Non-standard protocol", risk_score=0.5)

        hostname = normalize_hostname(url)
        registered_domain = get_registered_domain(hostname)
        full_domain = get_full_domain(hostname)
        path = parsed.path

        # ── 3. ML Prediction ──
        ml_result = predictor.predict(url)
        if ml_result:
            ml_score = ml_result["ensemble_score"]
            xgb_score = ml_result["xgb_score"]
            bert_score = ml_result["bert_score"]
            xgb_weight = ml_result["xgb_weight"]
        else:
            # Models not loaded — use 0.5 (uncertain) and rely on other layers
            ml_score = 0.5
            xgb_score = 0.5
            bert_score = 0.5
            xgb_weight = 0.5
            logger.warning("ML models not loaded, using fallback score")

        # ── 4. Domain Reputation ──
        reputation = get_reputation(hostname, url_path=path)
        dampened_ml = ml_score * reputation.dampening_factor

        logger.info(
            "ML=%.3f (xgb=%.3f, bert=%.3f) × dampen=%.2f → %.3f  [%s / %s]",
            ml_score, xgb_score, bert_score,
            reputation.dampening_factor, dampened_ml,
            reputation.tier.value, registered_domain,
        )

        # ── 5. Network Checks (parallel) ──
        net = await network_inspector.inspect_all(url, hostname, registered_domain)

        # ── 6. Compute Network Risk Adjustment ──
        network_risk, network_factors = self._compute_network_risk(net, reputation.tier)

        # ── 7. Heuristic Risk Factors ──
        risk_factors = get_risk_factors(url)
        risk_factors.extend(network_factors)

        # ── 8. Final Score ──
        final_score = (dampened_ml * self.ML_WEIGHT) + (network_risk * self.NETWORK_WEIGHT)
        final_score = max(0.0, min(1.0, final_score))

        # ── 9. Hard overrides ──
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
                    "ensemble_score": round(ml_score, 4),
                    "xgb_score": round(xgb_score, 4),
                    "bert_score": round(bert_score, 4),
                    "xgb_weight": round(xgb_weight, 2),
                    "dampened_score": round(dampened_ml, 4),
                },
                "domain": {
                    "registered_domain": registered_domain,
                    "full_domain": full_domain,
                    "reputation_tier": reputation.tier.value,
                    "dampening_factor": reputation.dampening_factor,
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

    def _compute_network_risk(self, net, tier: ReputationTier) -> tuple[float, list[str]]:
        """
        Compute a 0.0–1.0 risk score from network signals.
        Returns (score, list_of_factor_descriptions).
        """
        risk = 0.0
        factors: list[str] = []

        # DNS flags
        if "very_low_ttl" in net.dns.flags:
            risk += 0.10
            factors.append("Very low DNS TTL (fast-flux indicator)")
        if "no_mx_records" in net.dns.flags:
            risk += 0.05
            factors.append("No MX records")
        if "suspicious_nameserver" in net.dns.flags:
            risk += 0.10
            factors.append("Suspicious nameserver provider")

        # SSL
        if net.ssl.error == "ssl_verification_failed":
            risk += 0.20
            factors.append("SSL certificate verification failed")
        elif net.ssl.is_new_cert:
            risk += 0.10
            factors.append(f"SSL certificate is very new ({net.ssl.cert_age_days}d)")
        if not net.ssl.valid and net.ssl.error != "ssl_connection_failed":
            risk += 0.05

        # HTTP
        if net.http.redirect_count > 3:
            risk += 0.10
            factors.append(f"Excessive redirects ({net.http.redirect_count})")
        if net.http.redirect_domain_mismatch and tier != ReputationTier.SHORTENERS:
            risk += 0.15
            factors.append("Redirects to different domain")
        if net.http.scheme_warning:
            risk += 0.05
            factors.append("No HTTPS encryption")
        for flag in net.http.content_flags:
            if flag == "password_field":
                risk += 0.10
                factors.append("Page contains password field")
            elif flag == "billing_info_request":
                risk += 0.15
                factors.append("Page requests billing information")
            elif flag == "sensitive_id_request":
                risk += 0.15
                factors.append("Page requests sensitive ID")
            elif flag == "geolocation_tracking":
                risk += 0.10
                factors.append("Page tracks geolocation")
            elif flag == "obfuscated_javascript":
                risk += 0.15
                factors.append("Obfuscated JavaScript detected")
            elif flag == "excessive_iframes":
                risk += 0.10
                factors.append("Excessive iframes (click-jacking risk)")

        # WHOIS
        if net.whois.is_new_domain:
            risk += 0.15
            factors.append(f"Domain registered recently ({net.whois.age_days}d ago)")

        return min(1.0, risk), factors

    # ──────────────────────────────────────────────────────────
    # Decision Logic
    # ──────────────────────────────────────────────────────────

    def _decide(
        self,
        final_score: float,
        net,
        reputation,
        risk_factors: list[str],
    ) -> tuple[str, str]:
        """Return (status, message) based on all signals."""

        # Hard override: DNS failure = domain doesn't exist
        if net.dns.error == "domain_not_found":
            return "danger", "Domain does not exist (DNS failure)"

        # Hard override: server error
        if net.http.status_code and net.http.status_code >= 500:
            return "danger", f"Server error ({net.http.status_code})"

        # Hard override: site unreachable
        if net.http.error == "site_unreachable":
            return "danger", "Site is unreachable"

        # Score-based
        if final_score >= self.DANGER_THRESHOLD:
            top_factors = ", ".join(risk_factors[:3]) if risk_factors else "multiple signals"
            return "danger", f"High risk detected ({final_score:.0%}): {top_factors}"

        if final_score >= self.SUSPICIOUS_THRESHOLD:
            top_factors = ", ".join(risk_factors[:2]) if risk_factors else "elevated risk"
            return "suspicious", f"Suspicious patterns ({final_score:.0%}): {top_factors}"

        # Safe — add context
        tier = reputation.tier
        if tier == ReputationTier.CORPORATE:
            return "safe", "Verified safe — corporate site"
        if tier == ReputationTier.SERVICES:
            return "safe", "Verified safe — authenticated service"
        if tier == ReputationTier.UGC:
            return "safe", "No threats detected — user-generated content platform"
        if tier == ReputationTier.SHORTENERS:
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
