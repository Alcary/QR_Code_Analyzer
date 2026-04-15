"""
Tests for app/services/domain_reputation.py — _auth_bait_penalty.

Focuses on the token-based matching introduced to replace the previous
substring search, which produced false positives on paths like /author,
/authentication, and /github/authorization.
"""

import pytest

from app.services.domain_reputation import _auth_bait_penalty


# ── True negatives (must NOT fire) ───────────────────────────────
# These were all false positives with the old substring approach.

@pytest.mark.parametrize("path", [
    "/author",              # 'auth' is a substring but not a token
    "/authors",
    "/authentication",      # 'auth' is a prefix, not the whole segment
    "/github/authorization",  # 'auth' inside 'authorization'
    "/confirmation",        # 'confirm' is a prefix, not the whole segment
    "/accountant",          # 'account' is a prefix, not the whole segment
    "/",
    "",
    "/blog/post/1",
    "/products/checkout-summary",  # 'checkout' is not in the pattern set
])
def test_no_penalty_for_benign_paths(path):
    assert _auth_bait_penalty(path) == 0.0


# ── True positives (must fire) ────────────────────────────────────

@pytest.mark.parametrize("path,expected", [
    # Whole-segment matches
    ("/login",                    0.10),
    ("/signin",                   0.10),
    ("/verify",                   0.10),
    ("/auth",                     0.10),
    ("/oauth",                    0.10),
    ("/authorize",                0.10),
    ("/credential",               0.10),
    ("/suspended",                0.10),
    # Hyphenated whole-segment patterns in the frozenset
    ("/sign-in",                  0.10),
    ("/reset-password",           0.10),  # whole segment — must NOT double-count via 'password'
    ("/forgot-password",          0.10),  # same
    # Sub-part matches (segment itself is not in set)
    ("/my-account",               0.10),  # 'account' via sub-part
    ("/api/auth",                 0.10),  # 'auth' as a clean segment
    ("/user/login",               0.10),
    # File extensions stripped
    ("/login.php",                0.10),
    ("/signin.aspx",              0.10),
    ("/verify.html",              0.10),
    # Nested paths with multiple independent matches → additive, capped at 0.30
    ("/account/login",            0.20),  # 'account' + 'login'
    ("/user/verify/billing",      0.20),  # 'verify' + 'billing' ('user' is not a bait token)
    # Deep path with single match
    ("/api/v1/auth/token",        0.10),
    # Underscore separators
    ("/my_account/settings",      0.10),  # 'account' via '_' split
    ("/user_login",               0.10),  # 'login' via '_' split
])
def test_penalty_for_auth_bait_paths(path, expected):
    assert _auth_bait_penalty(path) == pytest.approx(expected)


# ── No double-counting for hyphenated whole-segment patterns ──────

def test_reset_password_counts_once():
    assert _auth_bait_penalty("/reset-password") == pytest.approx(0.10)


def test_forgot_password_counts_once():
    assert _auth_bait_penalty("/forgot-password") == pytest.approx(0.10)


# ── Cap at 0.30 ───────────────────────────────────────────────────

def test_penalty_capped_at_030():
    assert _auth_bait_penalty("/login/verify/billing/credential/suspend") == pytest.approx(0.30)


# ── Edge cases ────────────────────────────────────────────────────

def test_empty_path_returns_zero():
    assert _auth_bait_penalty("") == 0.0


def test_root_path_returns_zero():
    assert _auth_bait_penalty("/") == 0.0


def test_case_insensitive():
    assert _auth_bait_penalty("/LOGIN") == pytest.approx(0.10)
    assert _auth_bait_penalty("/My-Account") == pytest.approx(0.10)
