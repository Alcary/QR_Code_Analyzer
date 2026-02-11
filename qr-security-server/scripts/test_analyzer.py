"""
Test Script for URL Analyzer v2

This script tests the improved analyzer against various URLs
to verify that false positives have been reduced.

Run with: python -m scripts.test_analyzer
"""

import asyncio
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.analyzer import analyzer
from app.services.url_features import extract_features, get_risk_factors
from app.services.domain_whitelist import (
    get_reputation, 
    get_registered_domain,
    extract_domain_parts,
    normalize_hostname,
    ReputationTier,
    AUTH_BAIT_PATTERNS
)


# Test URLs categorized by expected result
TEST_CASES = {
    "safe": [
        # Common legitimate URLs that were causing false positives
        "https://docs.google.com/document/d/1234567890",
        "https://drive.google.com/file/d/abc123",
        "https://www.google.com/search?q=test",
        "https://github.com/user/repo",
        "https://stackoverflow.com/questions/12345",
        "https://www.amazon.com/dp/B08N5WRWNW",
        "https://www.linkedin.com/in/johndoe",
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "https://twitter.com/elonmusk",
        "https://www.reddit.com/r/programming",
        "https://medium.com/@user/article-title",
        "https://www.notion.so/workspace/page",
        "https://trello.com/b/abc123/board",
        "https://www.dropbox.com/s/abc123/file.pdf",
        "https://zoom.us/j/123456789",
        "https://meet.google.com/abc-defg-hij",
        "https://www.netflix.com/watch/12345",
        "https://open.spotify.com/track/abc123",
        "https://www.paypal.com/myaccount",
        "https://login.microsoftonline.com",
        # University/Education
        "https://www.mit.edu/admissions",
        "https://canvas.stanford.edu/courses/123",
        # News sites
        "https://www.bbc.com/news/world",
        "https://www.nytimes.com/2024/01/01/article.html",
    ],
    "suspicious": [
        # HTTP without encryption
        "http://example.com/login",
        # Long random-looking domains
        "https://a1b2c3d4e5f6g7h8.xyz/verify",
        # Suspicious TLDs
        "https://free-download.tk/software",
    ],
    "danger": [
        # Known malicious patterns
        "https://phish-example.com/verify-account",
        "https://malware-download.net/crack",
        # Non-existent domains (will fail DNS)
        "https://this-domain-definitely-does-not-exist-12345.com",
        # IP address URLs
        "http://192.168.1.1/admin/login.php",
    ]
}


async def test_url(url: str, expected_status: str) -> dict:
    """Test a single URL and return the result."""
    try:
        result = await analyzer.analyze(url)
        actual_status = result.get("status", "unknown")
        passed = actual_status == expected_status
        
        return {
            "url": url[:60] + "..." if len(url) > 60 else url,
            "expected": expected_status,
            "actual": actual_status,
            "passed": passed,
            "message": result.get("message", ""),
            "details": result.get("details", {})
        }
    except Exception as e:
        return {
            "url": url[:60] + "..." if len(url) > 60 else url,
            "expected": expected_status,
            "actual": "error",
            "passed": False,
            "message": str(e),
            "details": {}
        }


async def run_tests():
    """Run all test cases and print results."""
    print("=" * 70)
    print("URL Analyzer v2 - Test Suite")
    print("=" * 70)
    print()
    
    total_tests = 0
    passed_tests = 0
    failed_tests = []
    
    for expected_status, urls in TEST_CASES.items():
        print(f"\n--- Testing {expected_status.upper()} URLs ---\n")
        
        for url in urls:
            result = await test_url(url, expected_status)
            total_tests += 1
            
            if result["passed"]:
                passed_tests += 1
                status_icon = "[PASS]"
            else:
                status_icon = "[FAIL]"
                failed_tests.append(result)
            
            print(f"{status_icon} {result['url']}")
            print(f"  Expected: {result['expected']}, Got: {result['actual']}")
            
            # Show details for failures or interesting cases
            if not result["passed"] or expected_status == "danger":
                print(f"  Message: {result['message']}")
                if result['details']:
                    ml_score = result['details'].get('ml_risk_score', 'N/A')
                    combined = result['details'].get('combined_score', 'N/A')
                    tier = result['details'].get('reputation_tier', 'N/A')
                    print(f"  ML Score: {ml_score}, Combined: {combined}, Tier: {tier}")
            print()
    
    # Summary
    print("=" * 70)
    print(f"RESULTS: {passed_tests}/{total_tests} tests passed")
    print("=" * 70)
    
    if failed_tests:
        print("\nFailed Tests:")
        for test in failed_tests:
            print(f"  - {test['url']}: expected {test['expected']}, got {test['actual']}")
    
    return passed_tests == total_tests


def test_feature_extraction():
    """Test the URL feature extraction."""
    print("\n" + "=" * 70)
    print("URL Feature Extraction Tests")
    print("=" * 70 + "\n")
    
    test_urls = [
        "https://www.google.com/search?q=test",
        "https://a1b2c3d4e5.xyz/download",
        "http://192.168.1.1/admin",
        "https://login-verify-secure-account.tk/update?user=123&token=abc",
    ]
    
    for url in test_urls:
        features = extract_features(url)
        risk_factors = get_risk_factors(features)
        
        print(f"URL: {url}")
        print(f"  Domain Entropy: {features.domain_entropy:.2f}")
        print(f"  Subdomain Count: {features.subdomain_count}")
        print(f"  Heuristic Score: {features.heuristic_risk_score:.2%}")
        print(f"  Suspicious TLD: {features.is_suspicious_tld}")
        print(f"  Has IP Address: {features.has_ip_address}")
        if risk_factors:
            print(f"  Risk Factors: {', '.join(risk_factors)}")
        print()


def test_domain_extraction():
    """Test domain extraction with tldextract."""
    print("\n" + "=" * 70)
    print("Domain Extraction Tests (tldextract)")
    print("=" * 70 + "\n")
    
    test_domains = [
        "docs.google.com",
        "www.bbc.co.uk",
        "my.subdomain.example.org",
        "github.com",
        "user.github.io",
        "app.notion.site",
        "bit.ly",
        "192.168.1.1",
        "login.microsoftonline.com",
    ]
    
    for domain in test_domains:
        subdomain, name, suffix = extract_domain_parts(domain)
        registered = get_registered_domain(domain)
        print(f"Domain: {domain}")
        print(f"  Parts: subdomain='{subdomain}', domain='{name}', suffix='{suffix}'")
        print(f"  Registered Domain: {registered}")
        print()


def test_tiered_reputation():
    """Test the tiered reputation system."""
    print("\n" + "=" * 70)
    print("Tiered Reputation System Tests")
    print("=" * 70 + "\n")
    
    test_cases = [
        # (domain, expected_tier)
        ("google.com", ReputationTier.TIER_1_CORPORATE),
        ("docs.google.com", ReputationTier.TIER_3_UGC),
        ("drive.google.com", ReputationTier.TIER_3_UGC),
        ("sites.google.com", ReputationTier.TIER_3_UGC),
        ("github.com", ReputationTier.TIER_3_UGC),
        ("user.github.io", ReputationTier.TIER_3_UGC),
        ("linkedin.com", ReputationTier.TIER_2_SERVICES),
        ("bit.ly", ReputationTier.TIER_4_SHORTENERS),
        ("t.co", ReputationTier.TIER_4_SHORTENERS),
        ("bbc.co.uk", ReputationTier.TIER_1_CORPORATE),
        ("notion.site", ReputationTier.TIER_3_UGC),
        ("dropbox.com", ReputationTier.TIER_3_UGC),
        ("paypal.com", ReputationTier.TIER_2_SERVICES),
        ("random-unknown-site.com", ReputationTier.UNKNOWN),
        ("malicious.tk", ReputationTier.UNKNOWN),
    ]
    
    passed = 0
    failed = 0
    
    for domain, expected_tier in test_cases:
        reputation = get_reputation(domain)
        actual_tier = reputation.tier
        
        if actual_tier == expected_tier:
            status = "[PASS]"
            passed += 1
        else:
            status = "[FAIL]"
            failed += 1
        
        print(f"{status} {domain}")
        print(f"    Expected: {expected_tier.value}, Got: {actual_tier.value}")
        print(f"    Dampening: {reputation.dampening_factor}, Desc: {reputation.description}")
        print()
    
    print(f"Results: {passed}/{passed + failed} passed")
    return failed == 0


def test_hostname_normalizer():
    """Test the hostname normalizer function."""
    print("\n" + "=" * 70)
    print("Hostname Normalizer Tests")
    print("=" * 70 + "\n")
    
    test_cases = [
        # (input, expected_hostname)
        ("example.com", "example.com"),
        ("https://example.com", "example.com"),
        ("https://example.com:8080", "example.com"),
        ("https://example.com/path/to/page", "example.com"),
        ("https://example.com/path?query=value", "example.com"),
        ("https://user:pass@example.com", "example.com"),
        ("https://user:pass@example.com:8080/path?q=1", "example.com"),
        ("http://192.168.1.1:8080/admin", "192.168.1.1"),
        ("HTTPS://EXAMPLE.COM/PATH", "example.com"),  # Case normalization
        ("docs.google.com", "docs.google.com"),
        ("https://docs.google.com/document/d/123", "docs.google.com"),
        ("", ""),  # Empty string
    ]
    
    passed = 0
    failed = 0
    
    for input_str, expected in test_cases:
        actual = normalize_hostname(input_str)
        
        if actual == expected:
            status = "[PASS]"
            passed += 1
        else:
            status = "[FAIL]"
            failed += 1
        
        print(f"{status} '{input_str}'")
        print(f"    Expected: '{expected}', Got: '{actual}'")
    
    print(f"\nResults: {passed}/{passed + failed} passed")
    return failed == 0


def test_auth_bait_detection():
    """Test auth-bait detection on UGC platforms."""
    print("\n" + "=" * 70)
    print("Auth-Bait Detection Tests (UGC platforms)")
    print("=" * 70 + "\n")
    
    test_cases = [
        # (domain, path, expected_dampening)
        # Normal UGC URLs - should get 0.8 dampening
        ("docs.google.com", "/document/d/123", 0.8),
        ("github.com", "/user/repo/blob/main/file.py", 0.8),
        ("drive.google.com", "/file/d/abc123", 0.8),
        
        # Auth-bait URLs on UGC - should get NO dampening (1.0)
        ("docs.google.com", "/document/login-verify", 1.0),
        ("sites.google.com", "/secure/account/verify", 1.0),
        ("github.com", "/phishing-page/password-reset", 1.0),
        ("forms.google.com", "/oauth/authorize", 1.0),
        ("dropbox.com", "/billing/update-payment", 1.0),
        ("notion.so", "/suspended-account/unlock", 1.0),
        
        # Non-UGC platforms - shouldn't affect dampening
        ("google.com", "/account/login", 0.3),  # Tier 1, not UGC
        ("paypal.com", "/verify/account", 0.5),  # Tier 2, not UGC
        
        # Unknown domains - no dampening regardless
        ("random-site.com", "/login/verify", 1.0),
    ]
    
    passed = 0
    failed = 0
    
    for domain, path, expected_dampening in test_cases:
        reputation = get_reputation(domain, url_path=path)
        actual_dampening = reputation.dampening_factor
        
        if abs(actual_dampening - expected_dampening) < 0.01:
            status = "[PASS]"
            passed += 1
        else:
            status = "[FAIL]"
            failed += 1
        
        print(f"{status} {domain}{path}")
        print(f"    Tier: {reputation.tier.value}, Expected: {expected_dampening}, Got: {actual_dampening}")
        print(f"    Desc: {reputation.description}")
        print()
    
    print(f"Results: {passed}/{passed + failed} passed")
    return failed == 0


if __name__ == "__main__":
    # Run hostname normalizer tests (sync)
    test_hostname_normalizer()
    
    # Run domain extraction tests (sync)
    test_domain_extraction()
    
    # Run tiered reputation tests (sync)
    test_tiered_reputation()
    
    # Run auth-bait detection tests (sync)
    test_auth_bait_detection()
    
    # Run feature extraction tests (sync)
    test_feature_extraction()
    
    # Run main analyzer tests (async)
    asyncio.run(run_tests())
