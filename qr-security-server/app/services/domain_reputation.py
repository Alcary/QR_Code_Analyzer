"""
Domain reputation scoring module.

Computes a continuous trust score in [0, 1] from:
1. WHOIS domain age  — logistic curve normalisation (young = untrusted)
2. SSL certificate   — validity, age, days until expiry
3. DNS health        — resolution success, TTL stability, clean flags
4. Domain structure  — shortener detection, subdomain depth
5. Auth-bait path    — login/verify keywords in URL path (penalty)

Helper functions (normalize_hostname, extract_domain_parts, etc.)
are preserved from v1 to avoid breaking downstream imports.

Academic references:
    - Logistic domain-age curve: Hao et al. 2013 (NDSS)
    - SSL feature design: Bijmans et al. 2021 (IEEE S&P)
"""

import logging
import math
from enum import Enum
from typing import NamedTuple, Optional
from urllib.parse import urlparse

try:
    import tldextract
    _HAS_TLDEXTRACT = True
except ImportError:
    _HAS_TLDEXTRACT = False

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
# Types (backward compatible — enum values kept for API responses)
# ═══════════════════════════════════════════════════════════════

class ReputationTier(Enum):
    """Qualitative tier label derived from the computed trust score."""
    TRUSTED = "trusted"          # dampening ≤ 0.35
    MODERATE = "moderate"        # 0.35 < dampening ≤ 0.60
    NEUTRAL = "neutral"          # 0.60 < dampening ≤ 0.80
    UNTRUSTED = "untrusted"      # dampening > 0.80


class ReputationInfo(NamedTuple):
    tier: ReputationTier
    dampening_factor: float       # 0 = full trust, 1 = no trust
    description: str


# ═══════════════════════════════════════════════════════════════
# Known URL Shorteners (small, justified reference set)
# ═══════════════════════════════════════════════════════════════

KNOWN_SHORTENERS = frozenset({
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl",
    "ow.ly", "buff.ly", "is.gd", "v.gd", "rb.gy", "cutt.ly",
    "shorturl.at", "tiny.cc", "lnkd.in", "amzn.to",
    "rebrand.ly", "short.io",
})

# Auth-bait patterns — login/verify in path are suspicious on any domain
AUTH_BAIT_PATTERNS = frozenset({
    "login", "signin", "sign-in", "verify", "verification", "confirm",
    "account", "password", "reset-password", "forgot-password",
    "oauth", "authorize", "auth", "secure", "security", "billing",
    "suspend", "suspended", "locked", "unlock", "credential",
})


# ═══════════════════════════════════════════════════════════════
# Domain Extraction (preserved from v1)
# ═══════════════════════════════════════════════════════════════

def normalize_hostname(url_or_host: str) -> str:
    """Extract clean lowercase hostname from URL or hostname string."""
    if not url_or_host:
        return ""
    url_or_host = url_or_host.strip().lower()
    if "://" not in url_or_host:
        url_or_host = "https://" + url_or_host
    try:
        parsed = urlparse(url_or_host)
        return parsed.hostname or ""
    except Exception:
        return ""


def extract_domain_parts(url_or_domain: str) -> tuple[str, str, str]:
    """
    Extract (subdomain, domain, suffix) from a URL or hostname.
    Example: "docs.google.com" → ("docs", "google", "com")
    """
    hostname = normalize_hostname(url_or_domain)
    if not hostname:
        return "", "", ""

    if _HAS_TLDEXTRACT:
        ext = tldextract.extract(hostname)
        return ext.subdomain, ext.domain, ext.suffix

    # Fallback: simple split
    parts = hostname.split(".")
    if len(parts) < 2:
        return "", parts[0] if parts else "", ""
    compound = {"co", "com", "org", "net", "gov", "edu", "ac", "or"}
    if len(parts) >= 3 and parts[-2] in compound:
        return ".".join(parts[:-3]), parts[-3], f"{parts[-2]}.{parts[-1]}"
    return ".".join(parts[:-2]), parts[-2], parts[-1]


def get_registered_domain(url_or_domain: str) -> str:
    """Get registered domain: 'docs.google.com' → 'google.com'."""
    _, domain, suffix = extract_domain_parts(url_or_domain)
    if domain and suffix:
        return f"{domain}.{suffix}"
    return domain or url_or_domain


def get_full_domain(url_or_domain: str) -> str:
    """Get full domain: 'https://docs.google.com/x' → 'docs.google.com'."""
    sub, domain, suffix = extract_domain_parts(url_or_domain)
    parts = [p for p in [sub, domain, suffix] if p]
    return ".".join(parts)


# ═══════════════════════════════════════════════════════════════
# Computed Trust Score — Sub-functions
# ═══════════════════════════════════════════════════════════════

def _sigmoid(x: float, k: float = 1.0, x0: float = 0.0) -> float:
    """Standard logistic sigmoid: 1 / (1 + exp(-k * (x - x0)))."""
    return 1.0 / (1.0 + math.exp(-k * (x - x0)))


def _whois_trust(age_days: Optional[int]) -> float:
    """
    Compute 0–1 trust from domain age.

    Uses a logistic curve centred at 180 days (6 months).
    Very new domains (<30 days) → ~0.05 trust
    Moderate (6 months)         → ~0.50 trust
    Old (> 2 years)             → ~0.95 trust
    Unknown age                 → 0.30 (conservative neutral)

    Reference: Hao et al. 2013 — new domains are disproportionately malicious.
    """
    if age_days is None:
        return 0.30
    if age_days < 0:
        return 0.05  # future-dated creation → very suspicious
    # Logistic: k=0.015 gives nice spread, centred at 180 days
    return _sigmoid(age_days, k=0.015, x0=180)


def _ssl_trust(
    valid: Optional[bool],
    cert_age_days: Optional[int],
    days_until_expiry: Optional[int],
    error: Optional[str],
) -> float:
    """
    Compute 0–1 trust from SSL certificate properties.

    Clean SSL with an aged certificate → high trust.
    Brand new cert or failed verification → low trust.
    """
    if error == "ssl_verification_failed":
        return 0.0
    if error == "ssl_connection_failed" or valid is None:
        return 0.20  # could not connect — uncertain

    trust = 0.0
    if valid:
        trust += 0.50  # valid cert is a strong positive

    # Certificate age — older is better (capped at 365 days)
    if cert_age_days is not None:
        age_contribution = min(cert_age_days / 365.0, 1.0) * 0.30
        trust += age_contribution

    # Days until expiry — very short-lived certs are suspicious
    if days_until_expiry is not None:
        if days_until_expiry > 90:
            trust += 0.20
        elif days_until_expiry > 30:
            trust += 0.10
        # < 30 days or negative → no contribution

    return min(1.0, trust)


def _dns_trust(
    resolved: Optional[bool],
    ttl: Optional[int],
    flags: list[str],
) -> float:
    """
    Compute 0–1 trust from DNS resolution results.

    Resolution success + reasonable TTL + no flags → high trust.
    """
    if not resolved:
        return 0.0

    trust = 0.40  # resolved successfully

    # TTL: higher is more established (capped at 3600)
    if ttl is not None:
        if "very_low_ttl" not in flags:
            trust += min(ttl / 3600.0, 1.0) * 0.30

    # Clean flags bonus
    if not flags:
        trust += 0.30  # no suspicious flags at all
    else:
        trust -= len(flags) * 0.10

    return max(0.0, min(1.0, trust))


def _structure_trust(hostname: str) -> float:
    """
    Compute 0–1 trust from domain structural properties.

    Shorteners → 0.0 (destination hidden)
    Deep subdomains → penalized (e.g. secure.login.bank.example.com)
    Simple structure → higher trust
    """
    registered = get_registered_domain(hostname)

    if registered in KNOWN_SHORTENERS:
        return 0.0

    sub, _, _ = extract_domain_parts(hostname)
    subdomain_depth = len(sub.split(".")) if sub else 0

    trust = 0.80  # baseline for normal domains
    if subdomain_depth > 2:
        trust -= 0.30
    elif subdomain_depth > 1:
        trust -= 0.15

    return max(0.0, min(1.0, trust))


def _auth_bait_penalty(url_path: str) -> float:
    """
    Return a penalty in [0, 0.30] if the URL path contains
    authentication/credential-related keywords.
    """
    if not url_path:
        return 0.0
    path_lower = url_path.lower()
    matches = sum(1 for p in AUTH_BAIT_PATTERNS if p in path_lower)
    return min(matches * 0.10, 0.30)


# ═══════════════════════════════════════════════════════════════
# Main API — compute_domain_trust
# ═══════════════════════════════════════════════════════════════

def compute_domain_trust(
    hostname: str,
    url_path: str = "",
    whois_age_days: Optional[int] = None,
    ssl_valid: Optional[bool] = None,
    ssl_cert_age_days: Optional[int] = None,
    ssl_days_until_expiry: Optional[int] = None,
    ssl_error: Optional[str] = None,
    dns_resolved: Optional[bool] = None,
    dns_ttl: Optional[int] = None,
    dns_flags: Optional[list[str]] = None,
) -> ReputationInfo:
    """
    Compute a domain trust score from observable network signals.

    Parameters
    ----------
    hostname : str
        Normalised hostname (e.g. "docs.google.com").
    url_path : str
        URL path component for auth-bait detection.
    whois_age_days, ssl_*, dns_* :
        Network inspection results (from NetworkInspector).

    Returns
    -------
    ReputationInfo with:
        tier              — qualitative label
        dampening_factor  — continuous [0, 1] (0 = full trust, 1 = no trust)
        description       — human-readable explanation
    """
    w_whois = _whois_trust(whois_age_days)
    w_ssl = _ssl_trust(ssl_valid, ssl_cert_age_days, ssl_days_until_expiry, ssl_error)
    w_dns = _dns_trust(dns_resolved, dns_ttl, dns_flags or [])
    w_struct = _structure_trust(hostname)
    penalty = _auth_bait_penalty(url_path)

    # Weighted combination — each signal's contribution is chosen
    # based on its discriminative power from literature:
    #   WHOIS age   : 0.30 (Hao et al. 2013)
    #   SSL cert    : 0.25 (Bijmans et al. 2021)
    #   DNS health  : 0.25 (Bilge et al. 2011)
    #   Structure   : 0.20 (Ma et al. 2009)
    trust = (
        0.30 * w_whois
        + 0.25 * w_ssl
        + 0.25 * w_dns
        + 0.20 * w_struct
    )

    trust = max(0.0, trust - penalty)

    # Dampening factor = inverse of trust (1.0 = no trust, 0.0 = full trust)
    dampening = 1.0 - trust

    # Map to qualitative tier
    if dampening <= 0.35:
        tier = ReputationTier.TRUSTED
        desc = f"High trust (score={trust:.2f}): established domain"
    elif dampening <= 0.60:
        tier = ReputationTier.MODERATE
        desc = f"Moderate trust (score={trust:.2f})"
    elif dampening <= 0.80:
        tier = ReputationTier.NEUTRAL
        desc = f"Neutral trust (score={trust:.2f}): limited signals"
    else:
        tier = ReputationTier.UNTRUSTED
        desc = f"Low trust (score={trust:.2f}): weak or missing signals"

    if penalty > 0:
        desc += " — auth-bait path detected"

    logger.debug(
        "Domain trust %s: whois=%.2f ssl=%.2f dns=%.2f struct=%.2f "
        "penalty=%.2f → trust=%.2f dampening=%.2f [%s]",
        hostname, w_whois, w_ssl, w_dns, w_struct,
        penalty, trust, dampening, tier.value,
    )

    return ReputationInfo(tier, round(dampening, 4), desc)


# ═══════════════════════════════════════════════════════════════
# Backward-Compatible API (used by analyzer.py before network results)
# ═══════════════════════════════════════════════════════════════

def get_reputation(url_or_domain: str, url_path: str = "") -> ReputationInfo:
    """
    Backward-compatible wrapper.

    Without network signals this returns a structure-only estimate.
    The full compute_domain_trust() should be called from analyzer.py
    once network results are available.
    """
    hostname = normalize_hostname(url_or_domain)
    return compute_domain_trust(hostname, url_path=url_path)
