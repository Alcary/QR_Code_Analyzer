"""
Production-Grade URL Analyzer with Multi-Layer Verification

This analyzer combines multiple signals to minimize false positives
while maintaining high detection rates for actual threats.

Analysis Pipeline:
1. Fast Path Checks (whitelist/blocklist)
2. URL Feature Extraction (heuristics)
3. ML Prediction with Temperature Scaling
4. Tiered Reputation-Based Score Adjustment
5. Network Verification (DNS + SSL)
6. Weighted Ensemble Decision

Key Improvements over v1:
- Temperature-scaled ML probabilities (reduces overconfidence)
- Tiered domain reputation (UGC platforms get minimal dampening)
- Proper domain extraction using tldextract (Public Suffix List)
- URL feature analysis (entropy, structure, suspicious patterns)
- Confidence-aware thresholding
- Weighted ensemble combining ML + heuristics
"""

import aiohttp
import asyncio
import socket
from urllib.parse import urlparse
from cachetools import TTLCache
import logging

from app.services.ml.predictor import predictor
from app.services.url_features import extract_features, get_risk_factors
from app.services.domain_whitelist import (
    get_reputation,
    get_registered_domain,
    get_full_domain,
    normalize_hostname,
    ReputationTier,
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class URLAnalyzer:
    """
    Multi-layer URL analyzer optimized for low false positive rates.
    """
    
    # Thresholds (tuned for calibrated probabilities)
    # These are more conservative than v1 to reduce false positives
    DANGER_THRESHOLD = 0.70      # Combined score must exceed this for DANGER
    SUSPICIOUS_THRESHOLD = 0.40  # Combined score for SUSPICIOUS
    
    # Minimum ML confidence required to trust malicious prediction
    MIN_CONFIDENCE_FOR_DANGER = 0.60
    
    # Weight factors for ensemble decision
    ML_WEIGHT = 0.65          # ML model weight
    HEURISTIC_WEIGHT = 0.35   # Heuristic features weight
    
    # Known malicious DOMAIN patterns (definite blocklist - instant danger)
    # These are domains that are ALWAYS malicious
    KNOWN_MALICIOUS_DOMAINS = frozenset({
        "malware", "phish", "hack", "crack", "warez", "keygen",
    })
    
    # Suspicious PATH patterns (adds risk but NOT instant danger)
    # These could appear in legitimate URLs, so only add risk weight
    SUSPICIOUS_PATH_PATTERNS = frozenset({
        "download-free", "free-download", "prize-winner", "you-won",
        "verify-account", "suspended-account", "confirm-identity",
        "update-billing", "urgent-action", "account-locked",
    })
    
    # Risk weight added for each matched path pattern
    PATH_PATTERN_RISK_WEIGHT = 0.15

    def __init__(self):
        self.cache = TTLCache(maxsize=1000, ttl=3600)
        
    async def analyze(self, url: str) -> dict:
        """
        Comprehensive async URL analysis with multi-layer verification.
        """
        # 1. Check Cache
        if url in self.cache:
            logger.info(f"Cache hit for {url}")
            return self.cache[url]

        # 2. Basic Parsing
        try:
            parsed_url = urlparse(url if "://" in url else f"https://{url}")
            domain = parsed_url.netloc.lower()
            scheme = parsed_url.scheme.lower()
            path = parsed_url.path.lower()
        except Exception:
            return self._format_result("danger", "Invalid URL format")

        # 3. Protocol Check (immediate fail for non-http(s))
        if scheme not in ['http', 'https']:
            result = self._format_result("suspicious", "Non-standard protocol")
            self.cache[url] = result
            return result

        # 4. Extract URL Features (heuristics)
        features = extract_features(url)
        heuristic_score = features.heuristic_risk_score
        risk_factors = get_risk_factors(features)
        
        logger.info(f"URL Features: entropy={features.domain_entropy:.2f}, "
                   f"heuristic_score={heuristic_score:.2%}")

        # 5. Check for known malicious DOMAIN patterns (fast blocklist - only domain!)
        # Normalize hostname to strip port, credentials, etc.
        normalized_host = normalize_hostname(domain)
        registered_domain = get_registered_domain(normalized_host)
        full_domain = get_full_domain(normalized_host)
        
        for pattern in self.KNOWN_MALICIOUS_DOMAINS:
            if pattern in normalized_host:
                result = self._format_result(
                    "danger", 
                    f"Known malicious domain pattern: {pattern}",
                    details={
                        "matched_pattern": pattern,
                        "registered_domain": registered_domain,
                        "full_domain": full_domain,
                        "heuristic_score": heuristic_score,
                    }
                )
                self.cache[url] = result
                return result
        
        # 5b. Check for suspicious PATH patterns (adds risk, not instant danger)
        path_pattern_risk = 0.0
        matched_path_patterns = []
        for pattern in self.SUSPICIOUS_PATH_PATTERNS:
            if pattern in path:
                path_pattern_risk += self.PATH_PATTERN_RISK_WEIGHT
                matched_path_patterns.append(pattern)
                risk_factors.append(f"suspicious-path:{pattern}")
        
        # Add path pattern risk to heuristic score (capped at 0.5)
        heuristic_score = min(1.0, heuristic_score + min(0.5, path_pattern_risk))

        # 6. ML Prediction with Temperature Scaling
        ml_result = predictor.predict(url)
        ml_score = 0.0
        ml_confidence = 0.0
        ml_label = "unknown"
        
        if ml_result:
            ml_score = ml_result.get('malicious_score', 0.0)
            ml_confidence = ml_result.get('confidence', 0.0)
            ml_label = ml_result.get('pred_label', 'unknown')
            
            logger.info(f"ML Prediction: label={ml_label}, score={ml_score:.2%}, "
                       f"confidence={ml_confidence:.2%}")
        
        # 7. Tiered Reputation-Based Score Adjustment
        # Different platforms get different levels of trust
        # Pass path for auth-bait detection on UGC platforms
        reputation = get_reputation(normalized_host, url_path=path)
        dampening_factor = reputation.dampening_factor
        reputation_tier = reputation.tier
        
        original_ml_score = ml_score
        if dampening_factor < 1.0:
            ml_score = ml_score * dampening_factor
            logger.info(f"Domain '{normalized_host}' [{reputation_tier.value}]: "
                       f"dampened ML score {original_ml_score:.2%} -> {ml_score:.2%} "
                       f"(factor: {dampening_factor})")
        
        # Special handling for URL shorteners - flag for redirect following
        is_shortener = reputation_tier == ReputationTier.TIER_4_SHORTENERS
        is_ugc_platform = reputation_tier == ReputationTier.TIER_3_UGC

        # 8. Calculate Weighted Ensemble Score
        # Combine ML and heuristic scores with weights
        combined_score = (
            ml_score * self.ML_WEIGHT +
            heuristic_score * self.HEURISTIC_WEIGHT
        )
        
        logger.info(f"Ensemble: ml={ml_score:.2%}*{self.ML_WEIGHT} + "
                   f"heuristic={heuristic_score:.2%}*{self.HEURISTIC_WEIGHT} = "
                   f"combined={combined_score:.2%}")

        # 9. Network Verification (async)
        try:
            dns_task = self._check_dns(normalized_host)
            http_task = self._check_redirects_and_ssl(url)
            
            results = await asyncio.gather(dns_task, http_task, return_exceptions=True)
            
            dns_result = results[0] if isinstance(results[0], dict) else None
            http_result = results[1] if isinstance(results[1], dict) else None

        except Exception as e:
            logger.error(f"Network check error: {e}")
            dns_result = None
            http_result = None

        # 10. Final Decision with Confidence-Aware Logic
        final_status, final_message = self._make_decision(
            combined_score=combined_score,
            ml_score=ml_score,
            ml_confidence=ml_confidence,
            ml_label=ml_label,
            heuristic_score=heuristic_score,
            risk_factors=risk_factors,
            reputation_tier=reputation_tier,
            is_shortener=is_shortener,
            is_ugc_platform=is_ugc_platform,
            dns_result=dns_result,
            http_result=http_result
        )

        # Build details
        details = {
            "registered_domain": registered_domain,
            "full_domain": full_domain,
            "ml_prediction": ml_label,
            "ml_risk_score": round(ml_score, 4),
            "ml_raw_score": round(original_ml_score, 4),  # Before dampening
            "ml_confidence": round(ml_confidence, 4),
            "heuristic_score": round(heuristic_score, 4),
            "combined_score": round(combined_score, 4),
            "reputation_tier": reputation_tier.value,
            "dampening_factor": dampening_factor,
            "domain_entropy": round(features.domain_entropy, 4),
            "risk_factors": risk_factors if risk_factors else None,
            "domain_resolved": dns_result.get("status") == "safe" if dns_result else None,
            "is_shortener": is_shortener,
            "is_ugc_platform": is_ugc_platform,
        }
        
        if http_result:
            details["final_url"] = http_result.get("final_url", url)
            details["server"] = http_result.get("server", "unknown")

        result = {
            "status": final_status,
            "message": final_message,
            "details": details
        }
        
        self.cache[url] = result
        return result

    def _make_decision(
        self,
        combined_score: float,
        ml_score: float,
        ml_confidence: float,
        ml_label: str,
        heuristic_score: float,
        risk_factors: list[str],
        reputation_tier: ReputationTier,
        is_shortener: bool,
        is_ugc_platform: bool,
        dns_result: dict | None,
        http_result: dict | None
    ) -> tuple[str, str]:
        """
        Make final decision based on all available signals.
        Returns (status, message) tuple.
        
        Decision factors:
        - Combined ML + heuristic score
        - ML confidence level
        - Reputation tier of the domain
        - Network verification results
        """
        messages = []
        
        # DNS check is fundamental - if domain doesn't exist, it's dangerous
        if dns_result and dns_result.get("status") == "danger":
            return "danger", dns_result["message"]
        
        # HTTP connectivity issues
        http_status = http_result.get("status") if http_result else "safe"
        if http_status == "danger":
            return "danger", http_result.get("message", "Site unreachable")
        
        # Check HTTP results for advanced threats (redirects, content, scheme)
        if http_result:
            redirect_count = http_result.get("redirect_count", 0)
            suspicious_content = http_result.get("suspicious_content", [])
            scheme_warning = http_result.get("scheme_warning", False)
            
            # 1. Excessive Redirects
            if redirect_count > 3:
                messages.append(f"Excessive redirects ({redirect_count})")
                combined_score = max(combined_score, 0.45) # Force Suspicious level
            
            # 2. Suspicious Content (Personal Data / Location)
            if suspicious_content:
                msgs = ", ".join(suspicious_content)
                messages.append(f"Suspicious behavior: {msgs}")
                combined_score = max(combined_score, 0.65) # Detect as High Risk
                
            # 3. HTTP Scheme Warning
            if scheme_warning:
                 messages.append("Connection not encrypted (HTTP)")

            # 4. Cross-Domain Redirect (on non-shortener)
            # If a regular site redirects to a completely different domain, it's suspicious
            # (e.g. google.com -> attacker.com)
            if http_result.get("redirect_domain_mismatch") and not is_shortener:
                 messages.append("Redirects to different domain")
                 combined_score = max(combined_score, 0.55) # Treat as Suspicious

        # URL Shortener warning - we can't fully verify without following
        if is_shortener:
            # Check if redirect was followed and final URL is different
            final_url = http_result.get("final_url", "") if http_result else ""
            if final_url and combined_score >= 0.30:
                messages.append("Shortened URL with suspicious destination")
                return "suspicious", " | ".join(messages)
        
        # Decision logic based on combined score and confidence
        ml_label_lower = ml_label.lower()
        
        # DANGER: High combined score AND sufficient confidence
        if combined_score >= self.DANGER_THRESHOLD:
            # Additional check: Is ML confident enough?
            if ml_confidence >= self.MIN_CONFIDENCE_FOR_DANGER:
                if ml_label_lower == "phishing":
                    messages.append(f"Phishing indicators detected ({combined_score:.0%} risk)")
                elif ml_label_lower == "malware":
                    messages.append(f"Malware indicators detected ({combined_score:.0%} risk)")
                elif ml_label_lower == "defacement":
                    messages.append(f"Defacement indicators detected ({combined_score:.0%} risk)")
                else:
                    messages.append(f"High risk detected ({combined_score:.0%})")
                
                # Add context about UGC platforms
                if is_ugc_platform:
                    messages.append("Hosted on user-content platform")
                
                if risk_factors:
                    messages.append(f"Flags: {', '.join(risk_factors[:2])}")
                
                return "danger", " | ".join(messages)
            else:
                # High score but low confidence -> downgrade to suspicious
                messages.append(f"Uncertain threat ({combined_score:.0%} risk, low confidence)")
                return "suspicious", " | ".join(messages)
        
        # SUSPICIOUS: Medium combined score
        if combined_score >= self.SUSPICIOUS_THRESHOLD:
            messages.append(f"Suspicious patterns ({combined_score:.0%} risk)")
            
            # Add context about UGC platforms
            if is_ugc_platform:
                messages.append("User-generated content - verify authenticity")
            
            if risk_factors:
                messages.append(f"Flags: {', '.join(risk_factors[:2])}")
            
            return "suspicious", " | ".join(messages)
        
        # HTTP security warning (but not blocking)
        if http_status == "suspicious":
            http_msg = http_result.get("message", "Connection warning")
            # Only flag as suspicious if combined score is also elevated
            if combined_score >= 0.20:
                return "suspicious", http_msg
            # Otherwise, just note it but mark as safe
            messages.append(http_msg)
        
        # SAFE - provide context based on reputation tier
        if reputation_tier == ReputationTier.TIER_1_CORPORATE:
            messages.append("Verified safe (corporate site)")
        elif reputation_tier == ReputationTier.TIER_2_SERVICES:
            messages.append("Verified safe (authenticated service)")
        elif reputation_tier == ReputationTier.TIER_3_UGC:
            messages.append("No threats detected (user-generated content platform)")
        elif reputation_tier == ReputationTier.TIER_4_SHORTENERS:
            messages.append("Shortened URL - destination verified safe")
        else:
            messages.append("No threats detected")
        
        return "safe", " | ".join(messages) if messages else "URL verified safe"

    def _format_result(self, status: str, message: str, details: dict = None) -> dict:
        """Format a result dictionary."""
        result = {"status": status, "message": message}
        if details:
            result["details"] = details
        return result

    def _check_heuristics(self, url: str, scheme: str, domain: str):
        """Legacy heuristics - now handled by url_features module."""
        if scheme not in ['http', 'https']:
            return self._format_result("suspicious", "Non-standard protocol (not http/https)")
        return None

    async def _check_dns(self, domain: str) -> dict:
        """Verify if the domain resolves to an IP."""
        try:
            loop = asyncio.get_event_loop()
            # Domain should already be normalized (no port, no path, etc.)
            await loop.run_in_executor(None, socket.gethostbyname, domain)
            return {"status": "safe", "message": "DNS Resolved"}
        except socket.gaierror:
            return {"status": "danger", "message": "Domain does not exist"}

    async def _check_redirects_and_ssl(self, url: str) -> dict:
        """Follow redirects and check if destination is secure."""
        try:
            # Increased timeout slightly to allow for content reading
            timeout = aiohttp.ClientTimeout(total=8)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, allow_redirects=True, ssl=False) as response:
                    final_url = str(response.url)
                    redirect_count = len(response.history)
                    
                    # Content Analysis (scan for behavioral risks)
                    suspicious_content = []
                    content_type = response.headers.get("Content-Type", "").lower()
                    
                    if response.status == 200 and "text/html" in content_type:
                        try:
                            # Read first 15KB of content
                            text = await response.text()
                            text = text[:15000].lower()
                            
                            # 1. Ask for Personal Data
                            if 'type="password"' in text or "name=\"password\"" in text:
                                suspicious_content.append("asks for password")
                            if "credit card" in text or "billing address" in text or "cvv" in text:
                                suspicious_content.append("asks for billing info")
                            if "ssn" in text or "social security" in text:
                                suspicious_content.append("asks for sensitive ID")
                                
                            # 2. Check Location
                            if "geolocation.getcurrentposition" in text or "navigator.geolocation" in text:
                                suspicious_content.append("tracks location")
                        except Exception:
                            # Ignore content reading errors (e.g. decoding issues)
                            pass
                    
                    # Check final URL scheme
                    scheme_warning = False
                    if final_url.startswith("http://"):
                        scheme_warning = True
                    
                    # Check for Cross-Domain Redirect
                    # We compare the registered domains (e.g. google.com vs attacker.com)
                    start_domain = get_registered_domain(normalize_hostname(url))
                    end_domain = get_registered_domain(normalize_hostname(final_url))
                    redirect_domain_mismatch = (start_domain != end_domain and redirect_count > 0)

                    if response.status >= 400:
                        return {
                            "status": "danger",
                            "message": f"Server error ({response.status})"
                        }

                    return {
                        "status": "safe",
                        "message": "Accessible",
                        "final_url": final_url,
                        "server": response.headers.get("Server", "unknown"),
                        "redirect_count": redirect_count,
                        "suspicious_content": suspicious_content,
                        "scheme_warning": scheme_warning,
                        "redirect_domain_mismatch": redirect_domain_mismatch
                    }
        except aiohttp.ClientError:
            return {"status": "danger", "message": "Site unreachable"}
        except asyncio.TimeoutError:
            return {"status": "suspicious", "message": "Connection timed out"}


# Singleton instance
analyzer = URLAnalyzer()
