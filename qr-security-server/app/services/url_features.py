"""
URL Feature Extraction for ML Model

IMPORTANT: This module MUST produce features identical to the training notebook.
The feature names and their order are verified against feature_names.json at startup.

"""

import ipaddress
import re
import math
import numpy as np
from urllib.parse import urlparse, parse_qs, unquote
from collections import Counter

import tldextract

from app.services.homograph_detector import (
    extract_homograph_features,
    BRAND_DOMAINS as _BRAND_DOMAINS,
    _brand_in_label,
    _hostname_has_brand,
)

# Set of official brand domains used for strict "is official" checks
_OFFICIAL_BRAND_DOMAINS: frozenset[str] = frozenset(_BRAND_DOMAINS.values())


# ═══════════════════════════════════════════════════════════════
# Keyword / Pattern Dictionaries
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

# Common bigrams for domain randomness scoring.
# Includes standard English prose bigrams PLUS patterns common in
# legitimate domain names (e.g. "go", "oo", "ok", "bo", "ap", "eb").
_COMMON_BIGRAMS = frozenset({
    # Core English prose bigrams
    "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd",
    "ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar",
    "st", "to", "nt", "ng", "se", "ha", "as", "ou", "io", "le",
    "ve", "co", "me", "de", "hi", "ri", "ro", "ic", "ne", "ea",
    "ra", "ce", "li", "ch", "ll", "be", "ma", "si", "om", "ur",
    # Domain-typical bigrams (cover common brand names & tech words)
    "go", "oo", "og", "gl", "ok", "bo", "fa", "ac", "eb",
    "am", "az", "ap", "pl", "pp", "tw", "et", "fl", "ix",
    "pa", "sc", "ca", "op", "ub", "dr", "sp", "ot", "if",
    "so", "ft", "ab", "ad", "ob", "do", "ag", "gi", "ig",
    "po", "pi", "cr", "ct", "di", "mi", "mo", "no", "ov",
    "sh", "sk", "sl", "sn", "sw", "ta", "tr", "tu", "up",
    "ut", "wa", "wi", "wo", "zo",
})

# Suspicious keywords in domain names — direct indicator of bad intent
SUSPICIOUS_DOMAIN_KEYWORDS = frozenset({
    "scam", "phish", "phishing", "fraud", "hack", "hacking",
    "malware", "virus", "trojan", "ransomware", "spyware",
    "exploit", "botnet", "keylogger", "stealer", "spam",
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


def bigram_score(text: str) -> float:
    """
    Fraction of character bigrams that appear in common English bigrams.
    Real words have high scores (0.4-0.8), random strings have low (<0.2).
    """
    text = text.lower()
    letters = "".join(c for c in text if c.isalpha())
    if len(letters) < 2:
        return 0.0
    bigrams = [letters[i:i+2] for i in range(len(letters) - 1)]
    if not bigrams:
        return 0.0
    common_count = sum(1 for b in bigrams if b in _COMMON_BIGRAMS)
    return common_count / len(bigrams)


# ═══════════════════════════════════════════════════════════════
# Main Feature Extractor
# ═══════════════════════════════════════════════════════════════

def extract_features(url: str) -> dict:
    """
    Extract 95 features from a single URL.

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
    path = parsed.path
    query = parsed.query
    fragment = parsed.fragment

    # Domain extraction — use parsed.hostname which correctly handles
    # userinfo (http://user:pass@host), ports, and IPv6 brackets.
    domain = (parsed.hostname or "").lower()
    try:
        has_port = parsed.port is not None
    except ValueError:
        # Malformed port (non-numeric) — treat as no valid port
        has_port = False
    parts = domain.split(".")
    path_parts = [p for p in path.split("/") if p]

    # Use tldextract for accurate subdomain / registered-domain / TLD
    # parsing (handles multi-part TLDs like .co.uk, .com.au correctly)
    ext = tldextract.extract(domain)
    subdomain = ext.subdomain
    tld = ext.suffix or (parts[-1] if parts else "")

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
    f["avg_domain_part_len"] = float(np.mean([len(p) for p in parts])) if parts else 0.0
    f["longest_path_part"] = max((len(p) for p in path_parts), default=0)
    f["avg_path_part_len"] = float(np.mean([len(p) for p in path_parts])) if path_parts else 0.0

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
    f["subdomain_count"] = subdomain.count(".") + 1 if subdomain else 0
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
    f["has_port"] = int(has_port)
    f["has_at_symbol"] = int("@" in url)
    f["has_double_slash_in_path"] = int("//" in path)
    f["has_hex_encoding"] = int(unquote(url) != url)
    f["has_punycode"] = int("xn--" in domain)
    try:
        ipaddress.IPv4Address(domain)
        f["has_ip_address"] = 1
    except ValueError:
        f["has_ip_address"] = 0
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
    f["is_url_shortener"] = int(ext.top_domain_under_public_suffix in URL_SHORTENERS)
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
    # Strict official-domain check: compare full registrable domain
    # (e.g. "paypal.net") against known official brand domains ("paypal.com").
    # Using ext.domain (just the SLD, no TLD) was wrong: it would exempt
    # paypal.net because ext.domain == "paypal" which is in BRAND_KEYWORDS.
    f["brand_not_registered"] = int(
        f["brand_in_domain"] == 1
        and (ext.top_domain_under_public_suffix or "") not in _OFFICIAL_BRAND_DOMAINS
    )

    # ═══ HOMOGRAPH / TYPOSQUATTING ═══
    homo = extract_homograph_features(domain)
    f["homograph_has_mixed_scripts"] = homo["homograph_has_mixed_scripts"]
    f["homograph_confusable_chars"] = homo["homograph_confusable_chars"]
    f["homograph_min_brand_distance"] = homo["homograph_min_brand_distance"]
    f["homograph_has_char_sub"] = homo["homograph_has_char_sub"]
    f["homograph_is_exact_brand"] = homo["homograph_is_exact_brand"]

    # ═══ N-GRAM FEATURES (domain randomness) ═══
    domain_name_only = ext.domain or domain
    f["domain_bigram_score"] = bigram_score(domain_name_only)
    f["subdomain_bigram_score"] = bigram_score(subdomain) if subdomain else 0.0
    f["path_bigram_score"] = bigram_score("".join(path_parts)) if path_parts else 0.0

    return f


# Build canonical feature name list (same order as notebook)
FEATURE_NAMES = list(extract_features("https://www.example.com/path?q=1").keys())


def get_risk_factors(url: str) -> list[dict]:
    """
    Return structured risk factors derived from URL features.

    Each entry is a dict with keys: code, message, severity, evidence (optional).
    The ``code`` field is a stable machine-readable identifier; never change it
    without a schema migration because scoring logic and client rendering depend on it.

    Severity weights used in analyzer._compute_heuristic_risk:
        critical → 0.20   high → 0.12   medium → 0.06   low → 0.03
    """
    feats = extract_features(url)
    factors: list[dict] = []

    # ── Boundary-based brand signals (risk factors only) ──────────────────────
    # ML features (brand_in_domain, has_brand_in_subdomain, brand_not_registered)
    # use substring / SLD-only matching for training-parity and MUST NOT gate
    # user-facing risk factors.  Substring checks cause false positives on
    # unrelated words like "pineapple" (contains "apple") or "snapple".
    # We re-derive brand presence here using the same boundary-based matcher
    # that powers homograph_is_exact_brand, so the two layers are consistent.
    _rf_ext = tldextract.extract(url.lower())
    _registrable = _rf_ext.top_domain_under_public_suffix or ""
    _is_official_brand_domain = _registrable in _OFFICIAL_BRAND_DOMAINS
    # Does the SLD label (e.g. "paypal" in "paypal-secure.com") boundary-match
    # any known brand key?  _brand_in_label handles hyphen/digit separators
    # so "paypal-secure" matches "paypal" but "pineapple" does NOT match "apple".
    _domain_label = _rf_ext.domain or ""
    _boundary_brand_in_domain = any(
        _brand_in_label(_domain_label, brand) for brand in _BRAND_DOMAINS
    )
    # Does any dot-separated subdomain label boundary-match a brand?
    _subdomain_str = _rf_ext.subdomain or ""
    _boundary_brand_in_subdomain = bool(
        _subdomain_str
        and any(_hostname_has_brand(_subdomain_str, brand) for brand in _BRAND_DOMAINS)
    )

    def _rf(code: str, message: str, severity: str, evidence: str | None = None) -> dict:
        f: dict = {"code": code, "message": message, "severity": severity}
        if evidence is not None:
            f["evidence"] = evidence
        return f

    if feats.get("has_ip_address"):
        factors.append(_rf("ip_literal_url", "Uses IP address instead of domain name", "high"))
    if feats.get("has_at_symbol"):
        factors.append(_rf("credential_injection", "Contains @ symbol (credential injection risk)", "high"))
    if feats.get("has_double_slash_in_path"):
        factors.append(_rf("redirect_pattern", "Contains redirect pattern in path", "medium"))
    if feats.get("domain_entropy", 0) > 4.0:
        factors.append(_rf(
            "high_domain_entropy", "Domain appears randomly generated", "high",
            evidence=f"entropy={feats['domain_entropy']:.2f}",
        ))
    if feats.get("is_suspicious_tld"):
        factors.append(_rf("suspicious_tld", "Uses suspicious TLD", "medium"))
    if feats.get("subdomain_count", 0) > 3:
        n = feats["subdomain_count"]
        factors.append(_rf("excessive_subdomains", f"Excessive subdomains ({n})", "medium", evidence=str(n)))
    if feats.get("url_length", 0) > 200:
        factors.append(_rf("long_url", "Unusually long URL", "low", evidence=str(feats["url_length"])))
    if feats.get("has_port"):
        factors.append(_rf("non_standard_port", "Uses non-standard port", "medium"))
    if feats.get("has_punycode"):
        factors.append(_rf("punycode_domain", "Contains punycode (internationalized domain)", "medium"))
    # Use boundary-based matching (not substring / Levenshtein) so that
    # "pineapple.com" and "snapple.com" are never flagged for "apple".
    if _boundary_brand_in_domain and not _is_official_brand_domain:
        factors.append(_rf("brand_in_unofficial_domain", "Brand keyword in non-official domain", "high"))
    if _boundary_brand_in_subdomain:
        factors.append(_rf("brand_in_subdomain", "Brand name used in subdomain", "medium"))
    if feats.get("phishing_keyword_count", 0) >= 2:
        factors.append(_rf(
            "phishing_keywords", "Multiple phishing keywords detected", "medium",
            evidence=str(feats["phishing_keyword_count"]),
        ))
    if feats.get("has_dangerous_ext"):
        factors.append(_rf("dangerous_filetype", "Links to potentially dangerous file type", "high"))
    if feats.get("has_embedded_url"):
        factors.append(_rf("embedded_url", "URL embedded within path", "medium"))
    if feats.get("has_hex_encoding"):
        factors.append(_rf("hex_encoding", "Contains hex-encoded characters", "low"))
    if feats.get("is_url_shortener"):
        factors.append(_rf("url_shortener", "URL shortener — destination hidden", "medium"))
    if feats.get("has_data_uri"):
        factors.append(_rf("data_uri", "Data URI — may contain embedded content", "high"))
    if feats.get("has_javascript"):
        factors.append(_rf("javascript_protocol", "Contains javascript: protocol", "critical"))

    # ═══ Homograph / typosquatting ═══
    if feats.get("homograph_has_mixed_scripts"):
        factors.append(_rf("mixed_scripts", "Domain mixes scripts (IDN homograph attack indicator)", "high"))
    if feats.get("homograph_confusable_chars", 0) > 0:
        factors.append(_rf("confusable_chars", "Domain contains visually confusable characters", "high"))
    if feats.get("homograph_has_char_sub"):
        factors.append(_rf("char_substitution", "Character substitution detected (e.g., g00gle, paypa1)", "high"))
    if feats.get("homograph_is_exact_brand"):
        factors.append(_rf("brand_impersonation", "Domain impersonates a known brand", "critical"))
    # brand_lookalike: domain name is close to a known brand but not an exact
    # boundary match (that case is already covered by brand_in_unofficial_domain
    # or brand_impersonation above).
    # Extra-suspicion signals tighten the distance-2 case so that innocent
    # close strings like "snapple" (dist 2 to "apple", no confusables/char-sub)
    # are never flagged, while deliberate fakes like "gooogle.com" (dist 1) or
    # "paypa1.com" (char-sub) are still caught.
    _min_dist = feats.get("homograph_min_brand_distance", 999)
    _has_extra_suspicion = bool(
        feats.get("homograph_confusable_chars", 0) > 0
        or feats.get("homograph_has_char_sub")
        or feats.get("has_punycode")
        or feats.get("phishing_keyword_count", 0) > 0
    )
    if (
        (_min_dist <= 1 or (_min_dist == 2 and _has_extra_suspicion))
        and not _is_official_brand_domain
        and not _boundary_brand_in_domain  # already covered by brand_in_unofficial_domain
    ):
        factors.append(_rf("brand_lookalike", "Domain is suspiciously similar to a known brand", "high"))
    if feats.get("domain_bigram_score", 1.0) < 0.10:
        factors.append(_rf(
            "random_domain_bigram", "Domain name appears randomly generated", "high",
            evidence=f"bigram_score={feats['domain_bigram_score']:.3f}",
        ))

    # ═══ Suspicious keyword in domain ═══
    risk_ext = tldextract.extract(url)
    domain_word = risk_ext.domain or ""
    for kw in SUSPICIOUS_DOMAIN_KEYWORDS:
        if kw in domain_word:
            factors.append(_rf(
                "suspicious_domain_keyword",
                f"Suspicious keyword in domain name: '{kw}'",
                "high",
                evidence=kw,
            ))
            break

    return factors
