"""
Tiered Domain Reputation System

Classifies domains into trust tiers with dampening factors for ML risk scores.

Tiers:
- CORPORATE:   Main corporate sites (google.com, microsoft.com) → 0.3 dampening
- SERVICES:    Authenticated services (gmail.com, netflix.com)  → 0.5 dampening
- UGC:         User-generated content (github.com, docs.google.com) → 0.85 dampening
- SHORTENERS:  URL shorteners (bit.ly, t.co) → 1.0 (no dampening)
- UNKNOWN:     Everything else → 1.0 (no dampening)

IMPORTANT: High-reputation domains are NOT automatically safe!
UGC platforms like docs.google.com and github.io are heavily abused for phishing.
"""

import logging
from enum import Enum
from typing import NamedTuple
from urllib.parse import urlparse

try:
    import tldextract
    _HAS_TLDEXTRACT = True
except ImportError:
    _HAS_TLDEXTRACT = False

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
# Types
# ═══════════════════════════════════════════════════════════════

class ReputationTier(Enum):
    CORPORATE = "corporate"
    SERVICES = "services"
    UGC = "ugc"
    SHORTENERS = "shorteners"
    UNKNOWN = "unknown"


class ReputationInfo(NamedTuple):
    tier: ReputationTier
    dampening_factor: float
    description: str


TIER_DAMPENING = {
    ReputationTier.CORPORATE: 0.30,
    ReputationTier.SERVICES: 0.50,
    ReputationTier.UGC: 0.85,
    ReputationTier.SHORTENERS: 1.0,
    ReputationTier.UNKNOWN: 1.0,
}


# ═══════════════════════════════════════════════════════════════
# Domain Lists
# ═══════════════════════════════════════════════════════════════

TIER_1_CORPORATE = frozenset({
    # Tech
    "google.com", "microsoft.com", "apple.com", "amazon.com", "meta.com",
    "nvidia.com", "intel.com", "amd.com", "ibm.com", "oracle.com",
    "salesforce.com", "adobe.com", "cisco.com", "samsung.com", "dell.com",
    # Platforms
    "netflix.com", "spotify.com", "uber.com", "airbnb.com", "booking.com",
    # News
    "bbc.com", "bbc.co.uk", "cnn.com", "nytimes.com", "theguardian.com",
    "reuters.com", "bloomberg.com", "forbes.com", "wsj.com",
    # Reference
    "wikipedia.org", "wikimedia.org", "britannica.com",
    # Banks
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com",
    "capitalone.com", "americanexpress.com", "fidelity.com", "vanguard.com",
})

TIER_2_SERVICES = frozenset({
    # Email
    "gmail.com", "outlook.com", "proton.me", "protonmail.com",
    "yahoo.com", "icloud.com", "zoho.com",
    # Streaming (authenticated)
    "hulu.com", "disneyplus.com", "max.com", "crunchyroll.com",
    # Payments
    "paypal.com", "venmo.com", "wise.com", "revolut.com",
    # Professional
    "linkedin.com",
    # Workplace
    "slack.com", "zoom.us",
})

TIER_3_UGC = frozenset({
    # Google UGC
    "docs.google.com", "drive.google.com", "sheets.google.com",
    "slides.google.com", "forms.google.com", "sites.google.com",
    # Microsoft UGC
    "onedrive.com", "sharepoint.com", "forms.office.com",
    # Code hosting
    "github.com", "github.io", "gitlab.com", "gitlab.io",
    "bitbucket.org", "pages.dev", "vercel.app", "netlify.app",
    "herokuapp.com",
    # Cloud storage
    "dropbox.com", "box.com", "wetransfer.com", "mega.nz",
    # Notes / docs
    "notion.so", "notion.site", "coda.io",
    # Social media
    "facebook.com", "twitter.com", "x.com", "instagram.com",
    "reddit.com", "tumblr.com", "pinterest.com", "tiktok.com",
    "discord.com", "discord.gg", "t.me",
    # Blogging
    "medium.com", "substack.com", "wordpress.com", "blogger.com",
    "wix.com", "squarespace.com",
    # Paste / code sharing
    "pastebin.com", "codepen.io", "replit.com",
    # Video
    "youtube.com", "youtu.be", "vimeo.com", "twitch.tv",
    # Forums
    "stackoverflow.com", "stackexchange.com", "quora.com",
    # Forms (phishing vectors)
    "typeform.com", "surveymonkey.com", "jotform.com",
})

TIER_4_SHORTENERS = frozenset({
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl",
    "ow.ly", "buff.ly", "is.gd", "v.gd", "rb.gy", "cutt.ly",
    "shorturl.at", "tiny.cc", "lnkd.in", "amzn.to", "youtu.be",
    "rebrand.ly", "short.io",
})

# Auth-bait patterns — if found in UGC URL paths, remove dampening
AUTH_BAIT_PATTERNS = frozenset({
    "login", "signin", "sign-in", "verify", "verification", "confirm",
    "account", "password", "reset-password", "forgot-password",
    "oauth", "authorize", "auth", "secure", "security", "billing",
    "suspend", "suspended", "locked", "unlock", "credential",
})


# ═══════════════════════════════════════════════════════════════
# Domain Extraction
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
# Reputation Lookup
# ═══════════════════════════════════════════════════════════════

def get_reputation(url_or_domain: str, url_path: str = "") -> ReputationInfo:
    """
    Get the reputation tier and dampening factor for a domain.

    For UGC platforms, checks the URL path for auth-bait patterns
    (e.g. /login, /verify) which remove dampening entirely.
    """
    sub, domain, suffix = extract_domain_parts(url_or_domain)
    if not domain or not suffix:
        return ReputationInfo(ReputationTier.UNKNOWN, 1.0, "Invalid domain")

    registered = f"{domain}.{suffix}"
    full = f"{sub}.{domain}.{suffix}" if sub else registered

    # Tier 4 — URL shorteners (no trust)
    if registered in TIER_4_SHORTENERS or full in TIER_4_SHORTENERS:
        return ReputationInfo(
            ReputationTier.SHORTENERS, 1.0, "URL shortener — destination hidden"
        )

    # Tier 3 — UGC platforms
    if full in TIER_3_UGC or registered in TIER_3_UGC:
        dampening = TIER_DAMPENING[ReputationTier.UGC]
        desc = "User-generated content platform"

        if url_path:
            path_lower = url_path.lower()
            for pattern in AUTH_BAIT_PATTERNS:
                if pattern in path_lower:
                    dampening = 1.0
                    desc = f"UGC with auth-bait path: '{pattern}'"
                    break

        return ReputationInfo(ReputationTier.UGC, dampening, desc)

    # Tier 2 — Authenticated services
    if full in TIER_2_SERVICES or registered in TIER_2_SERVICES:
        return ReputationInfo(
            ReputationTier.SERVICES,
            TIER_DAMPENING[ReputationTier.SERVICES],
            "Authenticated service",
        )

    # Tier 1 — Corporate sites
    if registered in TIER_1_CORPORATE:
        return ReputationInfo(
            ReputationTier.CORPORATE,
            TIER_DAMPENING[ReputationTier.CORPORATE],
            "Corporate / official site",
        )

    return ReputationInfo(ReputationTier.UNKNOWN, 1.0, "Unknown domain")
