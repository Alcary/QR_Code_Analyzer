"""
Tiered Domain Reputation System

This module provides a sophisticated domain reputation system that:
1. Uses tldextract (Public Suffix List) for correct domain extraction
2. Implements tiered reputation levels with appropriate dampening factors
3. Distinguishes between corporate domains vs user-generated content platforms

IMPORTANT: High-reputation domains are NOT automatically safe!
Platforms like docs.google.com, github.com, etc. are frequently abused
by attackers to host phishing and malware. The dampening factor must
reflect this risk.

Reputation Tiers:
- TIER_1_CORPORATE: Main corporate sites (google.com homepage, microsoft.com homepage)
  → Moderate dampening (0.3) - Still need to verify paths
  
- TIER_2_SERVICES: Authenticated services (gmail.com, outlook.com, netflix.com)
  → Low dampening (0.5) - User must be logged in, harder to abuse
  
- TIER_3_UGC: User-Generated Content platforms (docs.google.com, github.com, notion.site)
  → Minimal dampening (0.8) - Anyone can create content, HIGH ABUSE RISK
  
- TIER_4_SHORTENERS: URL shorteners (bit.ly, t.co)
  → NO dampening (1.0) - Hide destination, must follow redirects
  
- UNKNOWN: Not in whitelist
  → NO dampening (1.0) - Full ML score applies
"""

import logging
import re
from typing import NamedTuple, Optional
from enum import Enum
from urllib.parse import urlparse

try:
    import tldextract
    TLDEXTRACT_AVAILABLE = True
except ImportError:
    TLDEXTRACT_AVAILABLE = False
    logging.warning("tldextract not installed. Using fallback domain extraction.")

logger = logging.getLogger(__name__)


# =============================================================================
# Hostname Normalizer
# Strips scheme, path, query, credentials, and port to get clean hostname
# =============================================================================
def normalize_hostname(url_or_host: str) -> str:
    """
    Extract a clean hostname from any URL or hostname string.
    
    Handles:
    - Full URLs with scheme: https://user:pass@example.com:8080/path?query
    - Hostnames with port: example.com:8080
    - Plain hostnames: example.com
    - Hostnames with credentials: user:pass@example.com
    
    Returns:
        Clean lowercase hostname without scheme, port, path, query, or credentials.
        Returns empty string if parsing fails.
    """
    if not url_or_host:
        return ""
    
    original = url_or_host
    url_or_host = url_or_host.strip().lower()
    
    # If no scheme, add one to enable proper URL parsing
    if "://" not in url_or_host:
        url_or_host = "https://" + url_or_host
    
    try:
        parsed = urlparse(url_or_host)
        hostname = parsed.hostname or ""
        
        # urlparse.hostname already strips port and credentials
        # Just need to ensure we have a valid hostname
        if hostname:
            return hostname
    except Exception:
        pass
    
    # Fallback: manual extraction
    try:
        # Remove scheme
        if "://" in url_or_host:
            url_or_host = url_or_host.split("://", 1)[1]
        
        # Remove path/query/fragment
        url_or_host = url_or_host.split("/", 1)[0]
        url_or_host = url_or_host.split("?", 1)[0]
        url_or_host = url_or_host.split("#", 1)[0]
        
        # Remove credentials (user:pass@)
        if "@" in url_or_host:
            url_or_host = url_or_host.split("@", 1)[1]
        
        # Remove port
        if ":" in url_or_host:
            url_or_host = url_or_host.split(":", 1)[0]
        
        return url_or_host
    except Exception:
        logger.warning(f"Failed to normalize hostname: {original}")
        return ""


class ReputationTier(Enum):
    """Domain reputation tiers with associated risk levels."""
    TIER_1_CORPORATE = "corporate"      # Main corporate sites
    TIER_2_SERVICES = "services"        # Authenticated services  
    TIER_3_UGC = "ugc"                  # User-generated content platforms
    TIER_4_SHORTENERS = "shorteners"    # URL shorteners (no trust)
    UNKNOWN = "unknown"                 # Not in whitelist


class ReputationInfo(NamedTuple):
    """Reputation information for a domain."""
    tier: ReputationTier
    dampening_factor: float  # Multiplier for ML risk score (lower = more trust)
    description: str
    requires_path_check: bool  # Whether to analyze URL path for additional risk


# Dampening factors per tier
# IMPORTANT: These are carefully tuned to balance false positives vs missed threats
TIER_DAMPENING = {
    ReputationTier.TIER_1_CORPORATE: 0.3,    # 70% reduction - main corporate sites
    ReputationTier.TIER_2_SERVICES: 0.5,     # 50% reduction - authenticated services
    ReputationTier.TIER_3_UGC: 0.8,          # 20% reduction - UGC platforms (HIGH RISK)
    ReputationTier.TIER_4_SHORTENERS: 1.0,   # No reduction - must follow redirects
    ReputationTier.UNKNOWN: 1.0,             # No reduction - unknown domains
}


# =============================================================================
# TIER 1: Corporate/Official Sites
# These are the main corporate homepages. Lower risk but still verify paths.
# =============================================================================
TIER_1_CORPORATE = frozenset({
    # Tech Giants (main sites only)
    "google.com", "microsoft.com", "apple.com", "amazon.com", "meta.com",
    "nvidia.com", "intel.com", "amd.com", "ibm.com", "oracle.com",
    "salesforce.com", "adobe.com", "cisco.com", "vmware.com",
    "samsung.com", "sony.com", "lg.com", "dell.com", "hp.com", "lenovo.com",
    
    # Major Platforms (corporate info, not UGC)
    "netflix.com", "spotify.com", "uber.com", "lyft.com", "airbnb.com",
    "booking.com", "expedia.com",
    
    # News Organizations (editorial control)
    "bbc.com", "bbc.co.uk", "cnn.com", "nytimes.com", "washingtonpost.com",
    "theguardian.com", "reuters.com", "apnews.com", "bloomberg.com",
    "forbes.com", "wsj.com", "ft.com", "economist.com",
    "npr.org", "pbs.org",
    
    # Reference (editorial control)
    "wikipedia.org", "wikimedia.org", "britannica.com",
    "merriam-webster.com", "dictionary.com",
    
    # Major Banks (heavily secured)
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com",
    "capitalone.com", "discover.com", "americanexpress.com",
    "schwab.com", "fidelity.com", "vanguard.com",
})

# =============================================================================
# TIER 2: Authenticated Services
# Require login, harder to abuse for phishing landing pages
# =============================================================================
TIER_2_SERVICES = frozenset({
    # Email (authenticated)
    "gmail.com", "outlook.com", "outlook.live.com", "proton.me", "protonmail.com",
    "yahoo.com", "aol.com", "icloud.com", "fastmail.com", "zoho.com",
    
    # Cloud Portals (authenticated dashboards)
    "console.cloud.google.com", "portal.azure.com", "console.aws.amazon.com",
    
    # Authenticated Services
    "account.google.com", "account.microsoft.com", "account.apple.com",
    "myaccount.google.com",
    
    # Streaming (authenticated)
    "netflix.com", "hulu.com", "disneyplus.com", "primevideo.com",
    "hbomax.com", "max.com", "peacocktv.com", "crunchyroll.com",
    
    # Payments (heavily secured, authenticated)
    "paypal.com", "venmo.com", "cashapp.com", "wise.com", "revolut.com",
    
    # Professional Networks (authenticated)
    "linkedin.com",
    
    # Workplace Tools (authenticated)
    "slack.com", "teams.microsoft.com", "zoom.us",
})

# =============================================================================
# TIER 3: User-Generated Content Platforms (HIGH RISK!)
# Anyone can create content on these - frequently abused for phishing/malware
# Only minimal dampening applied
# =============================================================================
TIER_3_UGC = frozenset({
    # Google UGC Services (HEAVILY ABUSED)
    "docs.google.com", "drive.google.com", "sheets.google.com",
    "slides.google.com", "forms.google.com", "sites.google.com",
    
    # Microsoft UGC
    "onedrive.com", "onedrive.live.com", "sharepoint.com",
    "forms.office.com", "sway.office.com",
    
    # Code Hosting (can host phishing pages)
    "github.com", "github.io",  # GitHub Pages can host any content
    "gitlab.com", "gitlab.io",
    "bitbucket.org",
    "pages.dev",  # Cloudflare Pages
    "vercel.app", "netlify.app",  # Hosting platforms
    "herokuapp.com",
    
    # Cloud Storage (shared files can be malware)
    "dropbox.com", "box.com", "wetransfer.com",
    "mediafire.com", "mega.nz", "mega.io",
    
    # Note/Doc Platforms (public pages)
    "notion.so", "notion.site",
    "coda.io", "airtable.com",
    
    # Social Media (anyone can post links)
    "facebook.com", "twitter.com", "x.com", "instagram.com",
    "reddit.com", "tumblr.com", "pinterest.com",
    "tiktok.com", "snapchat.com",
    "discord.com", "discord.gg",
    "telegram.org", "t.me",
    "whatsapp.com", "wa.me",
    
    # Blogging/Publishing (anyone can publish)
    "medium.com", "substack.com", "wordpress.com", "blogger.com",
    "wix.com", "squarespace.com", "weebly.com",
    
    # Paste/Code Sharing
    "pastebin.com", "codepen.io", "jsfiddle.net", "replit.com",
    
    # Video (user uploads)
    "youtube.com", "youtu.be", "vimeo.com", "dailymotion.com",
    "twitch.tv",
    
    # Forums/Q&A
    "stackoverflow.com", "stackexchange.com", "quora.com",
    
    # Gaming (user content)
    "steamcommunity.com", "itch.io",
    
    # Survey/Form Tools (phishing vectors)
    "typeform.com", "surveymonkey.com", "jotform.com",
})


# =============================================================================
# Auth-Bait Path Detection for UGC Platforms
# If a UGC URL contains these terms in the path, it's likely phishing
# =============================================================================
AUTH_BAIT_PATTERNS = frozenset({
    "login", "signin", "sign-in", "sign_in",
    "logout", "signout", "sign-out", "sign_out",
    "verify", "verification", "confirm", "confirmation",
    "account", "myaccount", "my-account", "my_account",
    "password", "passwd", "pwd", "reset-password", "forgot-password",
    "oauth", "oauth2", "authorize", "auth",
    "secure", "security", "update-info", "validate",
    "billing", "payment", "invoice",
    "suspend", "suspended", "locked", "unlock",
    "credential", "credentials",
})

# =============================================================================
# TIER 4: URL Shorteners (NO TRUST)
# These hide the actual destination - must follow redirects before judging
# =============================================================================
TIER_4_SHORTENERS = frozenset({
    "bit.ly", "bitly.com",
    "tinyurl.com",
    "t.co",  # Twitter
    "goo.gl",  # Google (deprecated but still works)
    "ow.ly",  # Hootsuite
    "buff.ly",  # Buffer
    "is.gd", "v.gd",
    "rb.gy",
    "cutt.ly",
    "shorturl.at",
    "tiny.cc",
    "lnkd.in",  # LinkedIn
    "youtu.be",  # YouTube short URLs
    "amzn.to",  # Amazon
    "rebrand.ly",
    "bl.ink",
    "short.io",
    "clck.ru",
    "qps.ru",
})


def extract_domain_parts(url_or_domain: str) -> tuple[str, str, str]:
    """
    Extract subdomain, domain, and suffix using tldextract.
    
    Returns:
        Tuple of (subdomain, domain, suffix)
        Example: "docs.google.com" -> ("docs", "google", "com")
                 "www.bbc.co.uk" -> ("www", "bbc", "co.uk")
    """
    # Normalize first to strip scheme, path, query, credentials, port
    hostname = normalize_hostname(url_or_domain)
    if not hostname:
        return "", "", ""
    
    if TLDEXTRACT_AVAILABLE:
        # Use tldextract with Public Suffix List
        extracted = tldextract.extract(hostname)
        return extracted.subdomain, extracted.domain, extracted.suffix
    else:
        # Fallback: simple split (NOT RECOMMENDED)
        return _fallback_extract(url_or_domain)


def _fallback_extract(domain: str) -> tuple[str, str, str]:
    """Fallback domain extraction when tldextract is not available."""
    # Normalize to get clean hostname
    hostname = normalize_hostname(domain)
    if not hostname:
        return "", "", ""
    
    parts = hostname.split(".")
    if len(parts) < 2:
        return "", parts[0] if parts else "", ""
    
    # Very basic compound TLD handling
    compound_tlds = {"co", "com", "org", "net", "gov", "edu", "ac", "or", "ne"}
    
    if len(parts) >= 3 and parts[-2] in compound_tlds:
        return ".".join(parts[:-3]), parts[-3], ".".join(parts[-2:])
    
    return ".".join(parts[:-2]), parts[-2], parts[-1]


def get_registered_domain(url_or_domain: str) -> str:
    """
    Get the registered domain (domain + suffix) from a URL or domain.
    
    Examples:
        "docs.google.com" -> "google.com"
        "www.bbc.co.uk" -> "bbc.co.uk"
        "my.subdomain.example.org" -> "example.org"
    """
    subdomain, domain, suffix = extract_domain_parts(url_or_domain)
    if domain and suffix:
        return f"{domain}.{suffix}"
    return domain or url_or_domain


def get_full_domain(url_or_domain: str) -> str:
    """
    Get the full domain (subdomain + domain + suffix) from a URL.
    
    Examples:
        "https://docs.google.com/doc/123" -> "docs.google.com"
    """
    subdomain, domain, suffix = extract_domain_parts(url_or_domain)
    parts = [p for p in [subdomain, domain, suffix] if p]
    return ".".join(parts)


def get_reputation(url_or_domain: str, url_path: str = "") -> ReputationInfo:
    """
    Get the reputation tier and dampening factor for a domain.
    
    This checks both the full domain (e.g., docs.google.com) and
    the registered domain (e.g., google.com) against the tier lists.
    
    Args:
        url_or_domain: The URL or domain to check
        url_path: Optional URL path for auth-bait detection on UGC platforms
    
    Returns:
        ReputationInfo with tier, dampening factor, and metadata
    """
    subdomain, domain, suffix = extract_domain_parts(url_or_domain)
    
    if not domain or not suffix:
        return ReputationInfo(
            tier=ReputationTier.UNKNOWN,
            dampening_factor=1.0,
            description="Invalid domain",
            requires_path_check=False
        )
    
    # Build domain variations to check
    registered_domain = f"{domain}.{suffix}"
    full_domain = f"{subdomain}.{domain}.{suffix}" if subdomain else registered_domain
    
    # Check Tier 4 first (URL shorteners) - these get NO trust
    if registered_domain in TIER_4_SHORTENERS or full_domain in TIER_4_SHORTENERS:
        return ReputationInfo(
            tier=ReputationTier.TIER_4_SHORTENERS,
            dampening_factor=TIER_DAMPENING[ReputationTier.TIER_4_SHORTENERS],
            description="URL shortener - destination hidden",
            requires_path_check=False  # Must follow redirect instead
        )
    
    # Check Tier 3 (UGC platforms) - check full domain first
    is_ugc = full_domain in TIER_3_UGC or registered_domain in TIER_3_UGC
    
    if is_ugc:
        # Check for auth-bait patterns in path - if found, NO dampening
        dampening = TIER_DAMPENING[ReputationTier.TIER_3_UGC]
        description = "User-generated content platform - verify content"
        
        if url_path:
            path_lower = url_path.lower()
            for pattern in AUTH_BAIT_PATTERNS:
                if pattern in path_lower:
                    # Auth-bait detected! Remove all dampening
                    dampening = 1.0
                    description = f"UGC platform with auth-bait path: '{pattern}'"
                    logger.warning(f"Auth-bait detected on UGC: {full_domain}{url_path} (pattern: {pattern})")
                    break
        
        return ReputationInfo(
            tier=ReputationTier.TIER_3_UGC,
            dampening_factor=dampening,
            description=description,
            requires_path_check=True  # Path matters for UGC
        )
    
    # Check Tier 2 (authenticated services)
    if full_domain in TIER_2_SERVICES or registered_domain in TIER_2_SERVICES:
        return ReputationInfo(
            tier=ReputationTier.TIER_2_SERVICES,
            dampening_factor=TIER_DAMPENING[ReputationTier.TIER_2_SERVICES],
            description="Authenticated service",
            requires_path_check=False
        )
    
    # Check Tier 1 (corporate sites)
    if registered_domain in TIER_1_CORPORATE:
        return ReputationInfo(
            tier=ReputationTier.TIER_1_CORPORATE,
            dampening_factor=TIER_DAMPENING[ReputationTier.TIER_1_CORPORATE],
            description="Corporate/official site",
            requires_path_check=False
        )
    
    # Unknown domain
    return ReputationInfo(
        tier=ReputationTier.UNKNOWN,
        dampening_factor=TIER_DAMPENING[ReputationTier.UNKNOWN],
        description="Unknown domain",
        requires_path_check=False
    )


# =============================================================================
# Legacy API (backward compatibility)
# =============================================================================

def get_root_domain(domain: str) -> str:
    """Legacy function - use get_registered_domain() instead."""
    return get_registered_domain(domain)


def is_high_reputation(domain: str) -> bool:
    """
    Legacy function - returns True if domain is in any reputation tier.
    
    WARNING: This does NOT mean the URL is safe! UGC platforms return True
    but should still be analyzed carefully.
    """
    reputation = get_reputation(domain)
    return reputation.tier != ReputationTier.UNKNOWN


def get_reputation_dampening_factor(domain: str, url_path: str = "") -> float:
    """
    Get the dampening factor for a domain's ML risk score.
    
    Returns a multiplier between 0.0 and 1.0:
    - Lower values = more trust = more dampening
    - 1.0 = no dampening (unknown or high-risk platforms)
    
    Args:
        domain: The domain to check
        url_path: Optional URL path for auth-bait detection on UGC platforms
    """
    reputation = get_reputation(domain, url_path)
    return reputation.dampening_factor
