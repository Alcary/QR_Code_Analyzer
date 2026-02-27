"""
Homograph & Typosquatting Detection

Detects:
1. IDN Homograph attacks — Cyrillic а (U+0430) vs Latin a (U+0061), etc.
2. Typosquatting — Levenshtein distance to known brand domains
3. Character substitution — g00gle, paypa1, amaz0n

These features are high-signal for phishing detection and are used
by both the heuristic risk factor generator and the ML feature extractor.
"""

import re
import unicodedata
from functools import lru_cache

import tldextract


# ═══════════════════════════════════════════════════════════════
# Confusable Unicode Mappings (most common attack vectors)
# ═══════════════════════════════════════════════════════════════

# Maps visually similar Unicode characters to their ASCII counterpart
CONFUSABLES: dict[str, str] = {
    # Cyrillic → Latin
    "\u0430": "a",  # а
    "\u0435": "e",  # е
    "\u043e": "o",  # о
    "\u0440": "p",  # р
    "\u0441": "c",  # с
    "\u0443": "y",  # у
    "\u0445": "x",  # х
    "\u044a": "b",  # ъ (visually similar in some fonts)
    "\u0456": "i",  # і (Ukrainian)
    "\u0458": "j",  # ј (Serbian)
    "\u04bb": "h",  # һ
    "\u0501": "d",  # ԁ
    # Greek → Latin
    "\u03b1": "a",  # α
    "\u03b5": "e",  # ε
    "\u03bf": "o",  # ο
    "\u03c1": "p",  # ρ
    "\u03ba": "k",  # κ
    "\u03bd": "v",  # ν
    "\u03c4": "t",  # τ
    "\u03b9": "i",  # ι
    # Common number/letter substitutions used by attackers
    "0": "o",
    "1": "l",
    "!": "i",
    "$": "s",
    "@": "a",
    "3": "e",
    "5": "s",
    "7": "t",
    "8": "b",
}

# Reverse mapping for detection: ASCII → set of confusable chars
_REVERSE_CONFUSABLES: dict[str, set[str]] = {}
for _conf, _ascii in CONFUSABLES.items():
    _REVERSE_CONFUSABLES.setdefault(_ascii, set()).add(_conf)


# ═══════════════════════════════════════════════════════════════
# Brand Targets (domains attackers most commonly impersonate)
# ═══════════════════════════════════════════════════════════════

BRAND_DOMAINS: dict[str, str] = {
    # brand_key: official domain (no www)
    "paypal": "paypal.com",
    "apple": "apple.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "amazon": "amazon.com",
    "facebook": "facebook.com",
    "netflix": "netflix.com",
    "instagram": "instagram.com",
    "whatsapp": "whatsapp.com",
    "twitter": "twitter.com",
    "linkedin": "linkedin.com",
    "ebay": "ebay.com",
    "dropbox": "dropbox.com",
    "icloud": "icloud.com",
    "outlook": "outlook.com",
    "yahoo": "yahoo.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "bankofamerica": "bankofamerica.com",
    "citibank": "citibank.com",
    "capitalone": "capitalone.com",
    "steam": "steampowered.com",
    "spotify": "spotify.com",
    "adobe": "adobe.com",
    "coinbase": "coinbase.com",
    "binance": "binance.com",
    "metamask": "metamask.io",
    "github": "github.com",
    "zoom": "zoom.us",
    "slack": "slack.com",
}


# ═══════════════════════════════════════════════════════════════
# Core Functions
# ═══════════════════════════════════════════════════════════════

def normalize_confusables(text: str) -> str:
    """
    Replace visually confusable characters with their ASCII equivalents.

    'pаypal' (with Cyrillic а) → 'paypal'
    'g00gle' → 'google'
    'paypa1' → 'paypal'
    """
    result = []
    for ch in text.lower():
        result.append(CONFUSABLES.get(ch, ch))
    return "".join(result)


def has_mixed_scripts(text: str) -> bool:
    """
    Check if a string mixes Latin with Cyrillic/Greek scripts.
    This is a strong indicator of an IDN homograph attack.
    Pure ASCII or pure Cyrillic domains are fine; mixing is not.
    """
    scripts = set()
    for ch in text:
        if ch in ".-_0123456789":
            continue
        cat = unicodedata.category(ch)
        if cat.startswith("L"):  # Letter
            name = unicodedata.name(ch, "").upper()
            if "CYRILLIC" in name:
                scripts.add("cyrillic")
            elif "GREEK" in name:
                scripts.add("greek")
            elif "LATIN" in name or ch.isascii():
                scripts.add("latin")
            else:
                scripts.add("other")
    return len(scripts) > 1


def count_confusable_chars(domain: str) -> int:
    """Count number of non-ASCII characters that are visually confusable with ASCII."""
    count = 0
    for ch in domain.lower():
        if ch in CONFUSABLES and not ch.isascii():
            count += 1
    return count


@lru_cache(maxsize=4096)
def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein (edit) distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            curr_row.append(min(
                curr_row[j] + 1,           # insert
                prev_row[j + 1] + 1,       # delete
                prev_row[j] + cost,        # replace
            ))
        prev_row = curr_row

    return prev_row[-1]


def min_brand_distance(domain: str) -> tuple[int, str]:
    """
    Compute the minimum Levenshtein distance from a domain to any known brand.

    Returns (min_distance, closest_brand_key).

    We compare against both:
    - The brand keyword ('paypal')
    - The full official domain ('paypal.com')
    And also compare after normalizing confusable characters.
    """
    # Strip common prefixes
    clean = domain.lower()
    if clean.startswith("www."):
        clean = clean[4:]
    normalized = normalize_confusables(clean)

    # Use tldextract for accurate domain name extraction
    # (handles multi-part TLDs like .co.uk correctly)
    ext = tldextract.extract(clean)
    domain_name = ext.domain or clean
    norm_domain_name = normalize_confusables(domain_name)

    best_dist = 999
    best_brand = ""

    for brand_key, brand_domain in BRAND_DOMAINS.items():
        d1 = levenshtein_distance(domain_name, brand_key)
        d2 = levenshtein_distance(norm_domain_name, brand_key)
        d3 = levenshtein_distance(clean, brand_domain)
        d4 = levenshtein_distance(normalized, brand_domain)

        dist = min(d1, d2, d3, d4)
        if dist < best_dist:
            best_dist = dist
            best_brand = brand_key

    return best_dist, best_brand


# ═══════════════════════════════════════════════════════════════
# Boundary-Based Brand Matching
# ═══════════════════════════════════════════════════════════════

def _brand_in_label(label: str, brand: str) -> bool:
    """
    Return True if *brand* appears as a complete token inside *label*.

    Matches (for brand="apple"):
      - exact label          : "apple"          → True
      - hyphen/underscore    : "secure-apple"   → True
      - brand+digits suffix  : "apple2"         → True
      - digits+brand prefix  : "2apple"         → True

    Does NOT match arbitrary substrings:
      - "pineapple"  → False   (apple is embedded, not a whole token)
      - "snapple"    → False
    """
    label = label.lower()
    brand = brand.lower()

    if label == brand:
        return True
    # Split by separators and check each token
    for token in re.split(r"[-_]", label):
        if token == brand:
            return True
        # brand[digits] or [digits]brand — still counted as brand impersonation
        if re.fullmatch(rf"{re.escape(brand)}\d+|\d+{re.escape(brand)}", token):
            return True
    return False


def _hostname_has_brand(hostname: str, brand: str) -> bool:
    """
    Return True if any dot-separated label in *hostname* contains *brand*
    as a whole token (via `_brand_in_label`).

    Splits "secure-apple.evil.com" into ["secure-apple", "evil", "com"]
    and checks each label.
    """
    labels = hostname.lower().rstrip(".").split(".")
    return any(_brand_in_label(label, brand) for label in labels)


def detect_char_substitution(domain: str) -> bool:
    """
    Detect leet-speak / character substitution in domain.
    E.g., g00gle, paypa1, amaz0n, micr0soft
    """
    # Strip TLD and www using tldextract
    ext = tldextract.extract(domain.lower())
    name = ext.domain or domain.lower()

    # Check if normalizing confusables changes the string AND matches a brand
    normalized = normalize_confusables(name)
    if normalized != name:
        for brand_key in BRAND_DOMAINS:
            if _brand_in_label(normalized, brand_key) and not _brand_in_label(name, brand_key):
                return True

    return False


# ═══════════════════════════════════════════════════════════════
# Feature Extraction (for ML model)
# ═══════════════════════════════════════════════════════════════

def extract_homograph_features(domain: str) -> dict:
    """
    Extract homograph/typosquatting features for the ML model.

    Returns dict with feature names and values:
    - homograph_has_mixed_scripts:  1 if domain mixes Latin + Cyrillic/Greek
    - homograph_confusable_chars:   count of confusable Unicode chars
    - homograph_min_brand_distance: Levenshtein distance to closest brand
    - homograph_has_char_sub:       1 if leet-speak substitution detected
    - homograph_is_exact_brand:     1 if domain matches brand after normalization
    """
    min_dist, closest = min_brand_distance(domain)

    # Check if after normalization, domain contains exact brand match
    normalized = normalize_confusables(domain.lower())
    clean_domain = domain.lower().rstrip(".")

    # Exempt only the registrable domain that exactly matches an official brand domain
    # (e.g. paypal.com, apple.com from BRAND_DOMAINS.values()).
    # Uses top_domain_under_public_suffix so paypal.co.uk is exempt but paypal.net is not.
    # Example: mail.google.co.il → top_domain="google.co.il" → NOT in official_domains
    #          google.com         → top_domain="google.com"   → in official_domains → exempt
    #          g00gle.com         → top_domain="g00gle.com"   → NOT in official_domains → flagged
    ext = tldextract.extract(clean_domain)
    registrable = ext.top_domain_under_public_suffix or clean_domain
    official_domains = set(BRAND_DOMAINS.values())
    is_official_domain = registrable in official_domains

    # Only flag impersonation if the domain contains a brand name
    # AND is NOT an official (sub)domain of that brand.
    # Use boundary-based matching: "pineapple.com" must NOT match "apple".
    is_exact_match = (
        any(_hostname_has_brand(normalized, b) for b in BRAND_DOMAINS)
        and not is_official_domain
    )

    return {
        "homograph_has_mixed_scripts": int(has_mixed_scripts(domain)),
        "homograph_confusable_chars": count_confusable_chars(domain),
        "homograph_min_brand_distance": min_dist,
        "homograph_has_char_sub": int(detect_char_substitution(domain)),
        # `min_dist <= 2` guard removed: boundary matching is already precise
        # so we no longer need it to suppress substring false-positives.
        "homograph_is_exact_brand": int(is_exact_match),
    }
