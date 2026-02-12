"""
URL Feature Extraction for ML Model

IMPORTANT: This module MUST produce features identical to the training notebook
(Model_Training_Colab.ipynb). Any changes here must also be reflected there.
The feature names and their order are verified against feature_names.json at startup.
"""

import re
import math
import numpy as np
from urllib.parse import urlparse, parse_qs
from collections import Counter


# ═══════════════════════════════════════════════════════════════
# Keyword / Pattern Dictionaries — MUST match notebook exactly
# ═══════════════════════════════════════════════════════════════

SUSPICIOUS_TLDS = frozenset({
    "tk", "ml", "ga", "cf", "gq", "pw", "top", "xyz", "club", "work",
    "click", "link", "surf", "buzz", "fun", "monster", "quest", "cam",
    "icu", "cc", "ws", "info", "biz", "su", "ru", "cn", "online", "site",
    "website", "space", "tech", "store", "stream", "download", "win",
    "review", "racing", "cricket", "science", "party", "gdn", "loan",
    "men", "country", "kim", "date", "faith", "accountant", "bid",
    "trade", "webcam",
})

TRUSTED_TLDS = frozenset({
    "edu", "gov", "mil", "int", "ac.uk", "gov.uk", "edu.au", "gov.au",
})

BRAND_KEYWORDS = frozenset({
    "paypal", "apple", "google", "microsoft", "amazon", "facebook",
    "netflix", "instagram", "whatsapp", "twitter", "linkedin", "ebay",
    "dropbox", "icloud", "outlook", "office365", "yahoo", "chase",
    "wellsfargo", "bankofamerica", "citibank", "capitalone", "steam",
    "spotify", "adobe", "coinbase", "binance", "metamask",
})

PHISHING_KEYWORDS = frozenset({
    "login", "signin", "sign-in", "logon", "password", "verify",
    "verification", "confirm", "update", "secure", "security", "account",
    "banking", "wallet", "suspend", "suspended", "urgent", "expire",
    "unlock", "restore", "recover", "validate", "authenticate", "webscr",
    "customer", "support", "helpdesk",
})

MALWARE_KEYWORDS = frozenset({
    "download", "free", "crack", "keygen", "patch", "serial", "warez",
    "torrent", "nulled", "hack", "cheat", "generator", "install", "setup",
    "update", "flash", "player", "codec", "driver",
})

URL_SHORTENERS = frozenset({
    "bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "t.co", "is.gd",
    "buff.ly", "adf.ly", "j.mp", "rb.gy", "cutt.ly", "tiny.cc",
})

DANGEROUS_EXTS = frozenset({
    ".exe", ".dll", ".bat", ".cmd", ".msi", ".scr", ".pif", ".vbs",
    ".js", ".jar", ".apk", ".dmg", ".zip", ".rar", ".7z", ".iso",
})


# ═══════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════

def calc_entropy(text: str) -> float:
    """Shannon entropy — higher = more random."""
    if not text:
        return 0.0
    freq = Counter(text.lower())
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values() if c > 0)


def max_run(text: str, cond) -> int:
    """Longest consecutive run of chars matching condition."""
    best = cur = 0
    for ch in text:
        if cond(ch):
            cur += 1
            best = max(best, cur)
        else:
            cur = 0
    return best


# ═══════════════════════════════════════════════════════════════
# Main Feature Extractor — identical to notebook
# ═══════════════════════════════════════════════════════════════

def extract_features(url: str) -> dict:
    """
    Extract 100+ features from a single URL.

    CRITICAL: This function must produce features identical to the training
    notebook. Do not modify without updating the notebook as well.
    """
    f = {}
    url = str(url).strip()

    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
    except Exception:
        return {k: 0 for k in FEATURE_NAMES}

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path
    query = parsed.query
    fragment = parsed.fragment

    # Domain cleanup
    netloc_no_port = (
        netloc.split(":")[0]
        if (":" in netloc and not netloc.startswith("["))
        else netloc
    )
    domain = netloc_no_port
    parts = domain.split(".")
    path_parts = [p for p in path.split("/") if p]
    subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""
    tld = parts[-1] if parts else ""
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "gov", "ac", "edu"):
        tld = f"{parts[-2]}.{parts[-1]}"

    url_lower = url.lower()
    path_lower = path.lower()

    # ═══ LENGTH ═══
    f["url_length"] = len(url)
    f["domain_length"] = len(domain)
    f["path_length"] = len(path)
    f["query_length"] = len(query)
    f["fragment_length"] = len(fragment)
    f["subdomain_length"] = len(subdomain)
    f["tld_length"] = len(tld)
    f["longest_domain_part"] = max((len(p) for p in parts), default=0)
    f["avg_domain_part_len"] = np.mean([len(p) for p in parts]) if parts else 0
    f["longest_path_part"] = max((len(p) for p in path_parts), default=0)
    f["avg_path_part_len"] = np.mean([len(p) for p in path_parts]) if path_parts else 0

    # ═══ COUNTS ═══
    for ch, name in [
        (".", "dot"), ("-", "hyphen"), ("_", "underscore"),
        ("/", "slash"), ("?", "question"), ("=", "equals"),
        ("&", "amp"), ("@", "at"), ("%", "percent"),
        ("~", "tilde"), ("#", "hash"), (":", "colon"),
        (";", "semicolon"),
    ]:
        f[f"{name}_count"] = url.count(ch)

    f["domain_dot_count"] = domain.count(".")
    f["domain_hyphen_count"] = domain.count("-")
    f["domain_digit_count"] = sum(c.isdigit() for c in domain)
    f["subdomain_count"] = max(0, len(parts) - 2)
    f["path_depth"] = len(path_parts)
    f["digit_count"] = sum(c.isdigit() for c in url)
    f["letter_count"] = sum(c.isalpha() for c in url)
    f["uppercase_count"] = sum(c.isupper() for c in url)
    f["special_char_count"] = sum(not c.isalnum() for c in url)

    try:
        qp = parse_qs(query)
        f["query_param_count"] = len(qp)
        f["query_value_total_len"] = sum(len(v) for vals in qp.values() for v in vals)
    except Exception:
        f["query_param_count"] = 0
        f["query_value_total_len"] = 0

    # ═══ RATIOS ═══
    ul = max(len(url), 1)
    dl = max(len(domain), 1)
    f["digit_ratio"] = f["digit_count"] / ul
    f["letter_ratio"] = f["letter_count"] / ul
    f["special_char_ratio"] = f["special_char_count"] / ul
    f["uppercase_ratio"] = f["uppercase_count"] / max(f["letter_count"], 1)
    f["domain_digit_ratio"] = f["domain_digit_count"] / dl
    f["domain_hyphen_ratio"] = f["domain_hyphen_count"] / dl
    f["path_url_ratio"] = f["path_length"] / ul
    f["query_url_ratio"] = f["query_length"] / ul
    f["domain_url_ratio"] = f["domain_length"] / ul

    # ═══ ENTROPY ═══
    f["url_entropy"] = calc_entropy(url)
    f["domain_entropy"] = calc_entropy(domain.replace(".", ""))
    f["path_entropy"] = calc_entropy(path)
    f["query_entropy"] = calc_entropy(query)
    f["subdomain_entropy"] = calc_entropy(subdomain)

    # ═══ BOOLEAN ═══
    f["is_https"] = int(scheme == "https")
    f["is_http"] = int(scheme == "http")
    f["has_www"] = int(domain.startswith("www."))
    f["has_port"] = int(":" in netloc and not netloc.startswith("["))
    f["has_at_symbol"] = int("@" in url)
    f["has_double_slash_in_path"] = int("//" in path)
    f["has_hex_encoding"] = int(bool(re.search(r"%[0-9a-fA-F]{2}", url)))
    f["has_punycode"] = int("xn--" in domain)
    f["has_ip_address"] = int(bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", domain)))
    f["has_hex_ip"] = int(bool(re.match(r"^(0x[0-9a-f]+\.){3}0x[0-9a-f]+$", domain)))
    f["has_ip_like"] = int(domain.replace(".", "").isdigit() and len(domain) > 6)

    # ═══ TLD ═══
    f["is_suspicious_tld"] = int(tld in SUSPICIOUS_TLDS)
    f["is_trusted_tld"] = int(tld in TRUSTED_TLDS)
    f["is_com"] = int(tld == "com")
    f["is_org"] = int(tld == "org")
    f["is_net"] = int(tld == "net")
    f["is_country_tld"] = int(len(tld) == 2 and tld.isalpha())

    # ═══ CHARACTER DISTRIBUTION ═══
    f["max_consec_digits"] = max_run(url, str.isdigit)
    f["max_consec_letters"] = max_run(url, str.isalpha)
    f["max_consec_special"] = max_run(url, lambda c: not c.isalnum())
    vowels = set("aeiou")
    dom_letters = [c for c in domain if c.isalpha()]
    f["domain_vowel_ratio"] = (
        sum(c in vowels for c in dom_letters) / max(len(dom_letters), 1)
    )

    # ═══ KEYWORDS ═══
    f["brand_keyword_count"] = sum(1 for b in BRAND_KEYWORDS if b in url_lower)
    f["has_brand_in_subdomain"] = int(any(b in subdomain.lower() for b in BRAND_KEYWORDS))
    f["phishing_keyword_count"] = sum(1 for k in PHISHING_KEYWORDS if k in url_lower)
    f["malware_keyword_count"] = sum(1 for k in MALWARE_KEYWORDS if k in url_lower)
    f["is_url_shortener"] = int(any(s in netloc for s in URL_SHORTENERS))
    f["has_dangerous_ext"] = int(any(path_lower.endswith(e) for e in DANGEROUS_EXTS))
    f["has_exe"] = int(path_lower.endswith(".exe"))
    f["has_php"] = int(".php" in path_lower)

    # ═══ STRUCTURAL PATTERNS ═══
    f["has_double_letters"] = int(bool(re.search(r"(.)\1", domain)))
    f["has_long_subdomain"] = int(len(subdomain) > 20)
    f["has_deep_path"] = int(len(path_parts) > 5)
    f["has_embedded_url"] = int("http" in path_lower or "www" in path_lower)
    f["has_data_uri"] = int(url_lower.startswith("data:"))
    f["has_javascript"] = int("javascript:" in url_lower)
    f["has_base64"] = int(bool(re.search(r"[A-Za-z0-9+/]{20,}={0,2}", url)))
    f["brand_in_domain"] = int(any(b in domain for b in BRAND_KEYWORDS))
    f["brand_not_registered"] = int(
        f["brand_in_domain"] == 1
        and not any(
            domain == f"{b}.com" or domain == f"www.{b}.com"
            for b in BRAND_KEYWORDS
        )
    )

    return f


# Build canonical feature name list (same order as notebook)
FEATURE_NAMES = list(extract_features("https://www.example.com/path?q=1").keys())


def get_risk_factors(url: str) -> list[str]:
    """Generate human-readable risk factor descriptions from URL features."""
    feats = extract_features(url)
    factors = []

    if feats.get("has_ip_address"):
        factors.append("Uses IP address instead of domain name")
    if feats.get("has_at_symbol"):
        factors.append("Contains @ symbol (credential injection risk)")
    if feats.get("has_double_slash_in_path"):
        factors.append("Contains redirect pattern in path")
    if feats.get("domain_entropy", 0) > 4.0:
        factors.append("Domain appears randomly generated")
    if feats.get("is_suspicious_tld"):
        factors.append("Uses suspicious TLD")
    if feats.get("subdomain_count", 0) > 3:
        factors.append(f"Excessive subdomains ({feats['subdomain_count']})")
    if feats.get("url_length", 0) > 200:
        factors.append("Unusually long URL")
    if feats.get("has_port"):
        factors.append("Uses non-standard port")
    if feats.get("has_punycode"):
        factors.append("Contains punycode (internationalized domain)")
    if feats.get("brand_not_registered"):
        factors.append("Brand keyword in non-official domain")
    if feats.get("has_brand_in_subdomain"):
        factors.append("Brand name used in subdomain")
    if feats.get("phishing_keyword_count", 0) >= 2:
        factors.append("Multiple phishing keywords detected")
    if feats.get("has_dangerous_ext"):
        factors.append("Links to potentially dangerous file type")
    if feats.get("has_embedded_url"):
        factors.append("URL embedded within path")
    if feats.get("has_hex_encoding"):
        factors.append("Contains hex-encoded characters")
    if feats.get("is_url_shortener"):
        factors.append("URL shortener — destination hidden")
    if feats.get("has_data_uri"):
        factors.append("Data URI — may contain embedded content")
    if feats.get("has_javascript"):
        factors.append("Contains javascript: protocol")

    return factors
