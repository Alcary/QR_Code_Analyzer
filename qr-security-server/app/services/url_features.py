"""
URL Feature Extraction for Heuristic Analysis

This module extracts lexical and statistical features from URLs
to complement ML predictions and reduce false positives.
"""

import re
import math
from urllib.parse import urlparse, parse_qs
from collections import Counter
from typing import NamedTuple


class URLFeatures(NamedTuple):
    """Structured URL features for analysis."""
    # Basic metrics
    url_length: int
    domain_length: int
    path_length: int
    query_length: int
    
    # Entropy (randomness measure)
    domain_entropy: float
    path_entropy: float
    full_entropy: float
    
    # Structural features
    subdomain_count: int
    path_depth: int
    query_param_count: int
    
    # Suspicious indicators
    has_ip_address: bool
    has_port: bool
    has_at_symbol: bool
    has_double_slash_redirect: bool
    has_hex_encoding: bool
    digit_ratio: float
    special_char_ratio: float
    
    # TLD info
    tld: str
    is_suspicious_tld: bool
    
    # Computed risk score (0.0 - 1.0)
    heuristic_risk_score: float


# Suspicious TLDs often used in phishing/malware
SUSPICIOUS_TLDS = frozenset({
    "tk", "ml", "ga", "cf", "gq",  # Free TLDs heavily abused
    "top", "xyz", "club", "work", "click", "link", "surf",
    "buzz", "fun", "monster", "quest", "cam", "icu",
    "pw", "cc", "ws", "info", "biz", "su", "ru", "cn",
})

# High-trust TLDs (educational, government)
TRUSTED_TLDS = frozenset({
    "edu", "gov", "mil", "int",
    "ac.uk", "gov.uk", "edu.au", "gov.au",
})


def calculate_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of a string.
    Higher entropy = more randomness (suspicious for domains).
    Normal domains: 2.5-3.5, Random/malicious: 4.0+
    """
    if not text:
        return 0.0
    
    # Count character frequencies
    freq = Counter(text.lower())
    length = len(text)
    
    # Calculate entropy
    entropy = 0.0
    for count in freq.values():
        if count > 0:
            prob = count / length
            entropy -= prob * math.log2(prob)
    
    return round(entropy, 4)


def extract_features(url: str) -> URLFeatures:
    """
    Extract comprehensive features from a URL for heuristic analysis.
    """
    try:
        parsed = urlparse(url if "://" in url else f"https://{url}")
    except Exception:
        # Return high-risk defaults for unparseable URLs
        return URLFeatures(
            url_length=len(url), domain_length=0, path_length=0, query_length=0,
            domain_entropy=5.0, path_entropy=5.0, full_entropy=5.0,
            subdomain_count=0, path_depth=0, query_param_count=0,
            has_ip_address=False, has_port=False, has_at_symbol=True,
            has_double_slash_redirect=True, has_hex_encoding=True,
            digit_ratio=0.5, special_char_ratio=0.5,
            tld="unknown", is_suspicious_tld=True,
            heuristic_risk_score=0.8
        )
    
    domain = parsed.netloc.lower()
    path = parsed.path
    query = parsed.query
    
    # Remove port from domain for analysis
    domain_no_port = domain.split(":")[0]
    
    # Basic lengths
    url_length = len(url)
    domain_length = len(domain_no_port)
    path_length = len(path)
    query_length = len(query)
    
    # Entropy calculations
    domain_entropy = calculate_entropy(domain_no_port.replace(".", ""))
    path_entropy = calculate_entropy(path)
    full_entropy = calculate_entropy(url)
    
    # Subdomain count
    domain_parts = domain_no_port.split(".")
    subdomain_count = max(0, len(domain_parts) - 2)  # Exclude root domain + TLD
    
    # Path depth
    path_depth = len([p for p in path.split("/") if p])
    
    # Query parameters
    try:
        query_params = parse_qs(query)
        query_param_count = len(query_params)
    except Exception:
        query_param_count = 0
    
    # Suspicious indicators
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    has_ip_address = bool(re.match(ip_pattern, domain_no_port))
    has_port = ":" in domain and not domain.startswith("[")  # Exclude IPv6
    has_at_symbol = "@" in url
    has_double_slash_redirect = "//" in path  # Redirect trick
    has_hex_encoding = "%" in url and re.search(r"%[0-9a-fA-F]{2}", url) is not None
    
    # Ratio calculations
    digits_in_domain = sum(c.isdigit() for c in domain_no_port)
    digit_ratio = digits_in_domain / max(1, domain_length)
    
    special_chars = sum(c in "-_~" for c in domain_no_port)
    special_char_ratio = special_chars / max(1, domain_length)
    
    # TLD extraction
    if len(domain_parts) >= 2:
        tld = domain_parts[-1]
        # Handle compound TLDs like .co.uk
        if len(domain_parts) >= 3 and domain_parts[-2] in ("co", "com", "org", "net", "gov", "ac"):
            tld = f"{domain_parts[-2]}.{domain_parts[-1]}"
    else:
        tld = domain_parts[-1] if domain_parts else "unknown"
    
    is_suspicious_tld = tld in SUSPICIOUS_TLDS
    is_trusted_tld = tld in TRUSTED_TLDS
    
    # Calculate heuristic risk score
    risk_score = _calculate_heuristic_risk(
        url_length=url_length,
        domain_entropy=domain_entropy,
        subdomain_count=subdomain_count,
        has_ip_address=has_ip_address,
        has_port=has_port,
        has_at_symbol=has_at_symbol,
        has_double_slash_redirect=has_double_slash_redirect,
        digit_ratio=digit_ratio,
        is_suspicious_tld=is_suspicious_tld,
        is_trusted_tld=is_trusted_tld,
        query_param_count=query_param_count,
        path_depth=path_depth
    )
    
    return URLFeatures(
        url_length=url_length,
        domain_length=domain_length,
        path_length=path_length,
        query_length=query_length,
        domain_entropy=domain_entropy,
        path_entropy=path_entropy,
        full_entropy=full_entropy,
        subdomain_count=subdomain_count,
        path_depth=path_depth,
        query_param_count=query_param_count,
        has_ip_address=has_ip_address,
        has_port=has_port,
        has_at_symbol=has_at_symbol,
        has_double_slash_redirect=has_double_slash_redirect,
        has_hex_encoding=has_hex_encoding,
        digit_ratio=digit_ratio,
        special_char_ratio=special_char_ratio,
        tld=tld,
        is_suspicious_tld=is_suspicious_tld,
        heuristic_risk_score=risk_score
    )


def _calculate_heuristic_risk(
    url_length: int,
    domain_entropy: float,
    subdomain_count: int,
    has_ip_address: bool,
    has_port: bool,
    has_at_symbol: bool,
    has_double_slash_redirect: bool,
    digit_ratio: float,
    is_suspicious_tld: bool,
    is_trusted_tld: bool,
    query_param_count: int,
    path_depth: int
) -> float:
    """
    Calculate a heuristic risk score based on URL features.
    Returns a value between 0.0 (safe) and 1.0 (dangerous).
    """
    score = 0.0
    
    # URL length (very long URLs are suspicious)
    if url_length > 200:
        score += 0.15
    elif url_length > 100:
        score += 0.05
    
    # Domain entropy (high entropy = random-looking = suspicious)
    if domain_entropy > 4.0:
        score += 0.20
    elif domain_entropy > 3.5:
        score += 0.10
    
    # Subdomain abuse (more than 3 subdomains is unusual)
    if subdomain_count > 4:
        score += 0.15
    elif subdomain_count > 2:
        score += 0.05
    
    # Direct IP access (no domain name)
    if has_ip_address:
        score += 0.25
    
    # Non-standard port
    if has_port:
        score += 0.10
    
    # @ symbol (credential injection trick)
    if has_at_symbol:
        score += 0.30
    
    # Double slash redirect trick
    if has_double_slash_redirect:
        score += 0.20
    
    # High digit ratio in domain
    if digit_ratio > 0.3:
        score += 0.10
    
    # Suspicious TLD
    if is_suspicious_tld:
        score += 0.15
    
    # Trusted TLD bonus (reduce score)
    if is_trusted_tld:
        score -= 0.20
    
    # Excessive query parameters
    if query_param_count > 5:
        score += 0.05
    
    # Very deep paths
    if path_depth > 6:
        score += 0.05
    
    # Clamp to [0, 1]
    return max(0.0, min(1.0, score))


def get_risk_factors(features: URLFeatures) -> list[str]:
    """
    Generate human-readable risk factor descriptions.
    """
    factors = []
    
    if features.has_ip_address:
        factors.append("Uses IP address instead of domain name")
    if features.has_at_symbol:
        factors.append("Contains @ symbol (credential injection risk)")
    if features.has_double_slash_redirect:
        factors.append("Contains redirect pattern in path")
    if features.domain_entropy > 4.0:
        factors.append("Domain appears randomly generated")
    if features.is_suspicious_tld:
        factors.append(f"Uses suspicious TLD (.{features.tld})")
    if features.subdomain_count > 3:
        factors.append(f"Excessive subdomains ({features.subdomain_count})")
    if features.url_length > 200:
        factors.append("Unusually long URL")
    if features.digit_ratio > 0.3:
        factors.append("High number of digits in domain")
    if features.has_port:
        factors.append("Uses non-standard port")
    
    return factors
