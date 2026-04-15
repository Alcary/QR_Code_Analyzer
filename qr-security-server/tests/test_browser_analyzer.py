"""
Tests for the browser analyzer client (app/services/browser_analyzer.py).

These are pure unit tests — no browser container needed.
They exercise:
  - BrowserResult data class defaults
  - compute_risk_signals() — risk scoring from browser features
  - _map_* helpers — JSON to BrowserResult mapping
  - Graceful degradation when browser analysis fails
"""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from app.services.browser_analyzer import (
    BrowserAnalyzer,
    BrowserResult,
    ContainerManager,
    _map_page_features,
    _map_network_features,
    _map_redirect_features,
    _map_brand_features,
)


# Shared instance — compute_risk_signals is stateless
_analyzer = BrowserAnalyzer(service_url="http://localhost:3000", timeout=15.0)


# ── Helpers ───────────────────────────────────────────────────


def _clean_result() -> BrowserResult:
    """A successful browser result with no risk signals."""
    return BrowserResult(success=True, has_favicon=True)


def _phishing_result() -> BrowserResult:
    """A browser result that looks like a phishing page."""
    r = BrowserResult(success=True)
    r.has_login_form = True
    r.has_password_field = True
    r.has_credit_card_input = True
    r.has_cvv_input = True
    r.external_form_action = True
    r.has_atob_eval = True
    r.has_eval_usage = True
    r.disables_right_click = True
    r.brand_domain_mismatch = True
    r.impersonated_brand = "paypal"
    r.has_urgency_text = True
    r.has_threat_text = True
    return r


# ── BrowserResult defaults ────────────────────────────────────


class TestBrowserResultDefaults:
    def test_default_success_is_false(self):
        r = BrowserResult()
        assert r.success is False
        assert r.error is None

    def test_all_bool_flags_default_false(self):
        r = BrowserResult()
        assert r.has_password_field is False
        assert r.has_login_form is False
        assert r.has_credit_card_input is False
        assert r.has_cvv_input is False
        assert r.has_ssn_input is False
        assert r.external_form_action is False
        assert r.has_eval_usage is False
        assert r.has_atob_eval is False
        assert r.disables_right_click is False
        assert r.brand_domain_mismatch is False
        assert r.has_urgency_text is False
        assert r.has_threat_text is False

    def test_all_counts_default_zero(self):
        r = BrowserResult()
        assert r.password_field_count == 0
        assert r.hidden_input_count == 0
        assert r.total_input_count == 0
        assert r.form_count == 0
        assert r.iframe_count == 0
        assert r.external_iframe_count == 0
        assert r.inline_script_count == 0
        assert r.external_script_count == 0
        assert r.total_script_count == 0
        assert r.total_requests == 0
        assert r.external_domain_count == 0
        assert r.page_load_ms == 0


# ── compute_risk_signals ──────────────────────────────────────


class TestComputeRiskSignals:
    def test_failed_result_returns_zero(self):
        r = BrowserResult(success=False, error="browser_timeout")
        risk, factors = _analyzer.compute_risk_signals(r)
        assert risk == 0.0
        assert factors == []

    def test_clean_page_returns_zero(self):
        risk, factors = _analyzer.compute_risk_signals(_clean_result())
        assert risk == 0.0
        assert factors == []

    def test_login_form_adds_risk(self):
        r = _clean_result()
        r.has_login_form = True
        risk, factors = _analyzer.compute_risk_signals(r)
        assert risk > 0.0
        codes = [f["code"] for f in factors]
        assert "browser_login_form" in codes

    def test_credit_card_input_high_risk(self):
        r = _clean_result()
        r.has_credit_card_input = True
        risk, factors = _analyzer.compute_risk_signals(r)
        assert risk >= 0.15
        assert any(f["severity"] == "high" for f in factors)

    def test_ssn_input_critical_severity(self):
        r = _clean_result()
        r.has_ssn_input = True
        risk, factors = _analyzer.compute_risk_signals(r)
        assert risk >= 0.15
        assert any(f["severity"] == "critical" for f in factors)

    def test_external_form_action(self):
        r = _clean_result()
        r.external_form_action = True
        risk, factors = _analyzer.compute_risk_signals(r)
        codes = [f["code"] for f in factors]
        assert "browser_external_form" in codes

    def test_js_obfuscation_multiple_signals(self):
        r = _clean_result()
        r.has_eval_usage = True
        r.has_atob_eval = True
        r.has_fromcharcode = True
        risk, factors = _analyzer.compute_risk_signals(r)
        codes = [f["code"] for f in factors]
        assert "browser_js_obfuscation" in codes
        assert risk >= 0.15

    def test_single_atob_eval(self):
        r = _clean_result()
        r.has_atob_eval = True
        risk, factors = _analyzer.compute_risk_signals(r)
        codes = [f["code"] for f in factors]
        assert "browser_eval_atob" in codes

    def test_many_external_script_domains(self):
        r = _clean_result()
        r.external_script_domains = 12
        risk, factors = _analyzer.compute_risk_signals(r)
        codes = [f["code"] for f in factors]
        assert "browser_many_script_domains" in codes

    def test_few_external_script_domains_no_risk(self):
        r = _clean_result()
        r.external_script_domains = 3
        risk, factors = _analyzer.compute_risk_signals(r)
        codes = [f["code"] for f in factors]
        assert "browser_many_script_domains" not in codes

    def test_right_click_disabled(self):
        r = _clean_result()
        r.disables_right_click = True
        risk, factors = _analyzer.compute_risk_signals(r)
        codes = [f["code"] for f in factors]
        assert "browser_no_right_click" in codes

    def test_devtools_detection(self):
        r = _clean_result()
        r.has_devtools_detection = True
        risk, factors = _analyzer.compute_risk_signals(r)
        codes = [f["code"] for f in factors]
        assert "browser_devtools_detection" in codes

    def test_brand_impersonation_critical(self):
        r = _clean_result()
        r.brand_domain_mismatch = True
        r.impersonated_brand = "google"
        risk, factors = _analyzer.compute_risk_signals(r)
        assert risk >= 0.20
        assert any(f["severity"] == "critical" for f in factors)
        assert any("google" in f.get("evidence", "") for f in factors)

    def test_brand_mismatch_without_brand_no_factor(self):
        r = _clean_result()
        r.brand_domain_mismatch = True
        r.impersonated_brand = None
        risk, factors = _analyzer.compute_risk_signals(r)
        codes = [f["code"] for f in factors]
        assert "browser_brand_impersonation" not in codes

    def test_urgency_text(self):
        r = _clean_result()
        r.has_urgency_text = True
        risk, factors = _analyzer.compute_risk_signals(r)
        codes = [f["code"] for f in factors]
        assert "browser_urgency_language" in codes

    def test_threat_text(self):
        r = _clean_result()
        r.has_threat_text = True
        risk, factors = _analyzer.compute_risk_signals(r)
        codes = [f["code"] for f in factors]
        assert "browser_threat_language" in codes

    def test_hidden_content(self):
        r = _clean_result()
        r.hidden_elements_with_content = 8
        risk, factors = _analyzer.compute_risk_signals(r)
        codes = [f["code"] for f in factors]
        assert "browser_hidden_content" in codes

    def test_low_hidden_content_no_risk(self):
        r = _clean_result()
        r.hidden_elements_with_content = 2
        risk, factors = _analyzer.compute_risk_signals(r)
        codes = [f["code"] for f in factors]
        assert "browser_hidden_content" not in codes

    def test_external_iframes(self):
        r = _clean_result()
        r.external_iframe_count = 4
        risk, factors = _analyzer.compute_risk_signals(r)
        codes = [f["code"] for f in factors]
        assert "browser_external_iframes" in codes

    def test_domain_changed_via_js(self):
        r = _clean_result()
        r.domain_changed = True
        r.final_url = "https://evil.com"
        risk, factors = _analyzer.compute_risk_signals(r)
        codes = [f["code"] for f in factors]
        assert "browser_js_redirect" in codes

    def test_phishing_page_high_risk(self):
        """A full phishing page should produce a high combined risk."""
        risk, factors = _analyzer.compute_risk_signals(_phishing_result())
        assert risk >= 0.70
        assert len(factors) >= 5

    def test_risk_capped_at_1(self):
        """Even with all signals, risk should not exceed 1.0."""
        r = _phishing_result()
        r.has_ssn_input = True
        r.has_devtools_detection = True
        r.external_iframe_count = 5
        r.hidden_elements_with_content = 10
        r.domain_changed = True
        r.external_script_domains = 15
        risk, _ = _analyzer.compute_risk_signals(r)
        assert risk <= 1.0

    def test_all_factors_have_required_fields(self):
        """Every risk factor must have code, message, and severity."""
        _, factors = _analyzer.compute_risk_signals(_phishing_result())
        for f in factors:
            assert "code" in f
            assert "message" in f
            assert "severity" in f
            assert f["severity"] in ("low", "medium", "high", "critical")


# ── Mapping helpers ───────────────────────────────────────────


class TestMappingHelpers:
    def test_map_page_features(self):
        r = BrowserResult()
        pf = {
            "has_password_field": True,
            "password_field_count": 2,
            "has_login_form": True,
            "has_credit_card_input": False,
            "iframe_count": 3,
            "external_script_count": 5,
            "has_eval_usage": True,
            "page_title": "Test Page",
        }
        _map_page_features(r, pf)
        assert r.has_password_field is True
        assert r.password_field_count == 2
        assert r.has_login_form is True
        assert r.has_credit_card_input is False
        assert r.iframe_count == 3
        assert r.external_script_count == 5
        assert r.has_eval_usage is True
        assert r.page_title == "Test Page"

    def test_map_page_features_missing_keys(self):
        r = BrowserResult()
        _map_page_features(r, {})
        assert r.has_password_field is False
        assert r.iframe_count == 0

    def test_map_network_features(self):
        r = BrowserResult()
        nf = {
            "total_requests": 47,
            "external_domain_count": 8,
            "external_script_domains": 3,
        }
        _map_network_features(r, nf)
        assert r.total_requests == 47
        assert r.external_domain_count == 8
        assert r.external_script_domains == 3

    def test_map_redirect_features(self):
        r = BrowserResult()
        rf = {
            "url_changed": True,
            "domain_changed": True,
            "final_url": "https://other.com",
        }
        _map_redirect_features(r, rf)
        assert r.url_changed is True
        assert r.domain_changed is True
        assert r.final_url == "https://other.com"

    def test_map_brand_features(self):
        r = BrowserResult()
        bf = {
            "detected_brands": ["paypal", "google"],
            "brand_domain_mismatch": True,
            "impersonated_brand": "paypal",
        }
        _map_brand_features(r, bf)
        assert r.detected_brands == ["paypal", "google"]
        assert r.brand_domain_mismatch is True
        assert r.impersonated_brand == "paypal"


# ── ContainerManager.ensure_running — lock / generation counter ─


class TestEnsureRunning:
    """
    Tests for the generation-counter restart serialisation in ensure_running().

    All tests mock _is_healthy() and start() so no Docker daemon is needed.
    """

    def _manager(self) -> ContainerManager:
        return ContainerManager()

    # Fast path: healthy container skips the lock and never calls start()
    @pytest.mark.asyncio
    async def test_healthy_returns_true_without_restart(self):
        mgr = self._manager()
        with patch.object(mgr, "_is_healthy", AsyncMock(return_value=True)):
            with patch.object(mgr, "start", AsyncMock()) as mock_start:
                result = await mgr.ensure_running()

        assert result is True
        mock_start.assert_not_called()

    @pytest.mark.asyncio
    async def test_unhealthy_triggers_restart(self):
        mgr = self._manager()
        with patch.object(mgr, "_is_healthy", AsyncMock(return_value=False)):
            with patch.object(mgr, "start", AsyncMock(return_value=True)) as mock_start:
                result = await mgr.ensure_running()

        assert result is True
        mock_start.assert_called_once()
        assert mgr._restart_generation == 1
        assert mgr._last_restart_ok is True

    # Many coroutines seeing an unhealthy container must trigger exactly one restart;
    # the generation counter prevents the rest from calling start() redundantly.
    @pytest.mark.asyncio
    async def test_restart_called_once_under_concurrent_requests(self):
        mgr = self._manager()
        start_calls = 0

        async def fake_start():
            nonlocal start_calls
            start_calls += 1
            await asyncio.sleep(0)  # yield so other coroutines can queue on the lock
            return True

        with patch.object(mgr, "_is_healthy", AsyncMock(return_value=False)):
            with patch.object(mgr, "start", side_effect=fake_start):
                results = await asyncio.gather(
                    *[mgr.ensure_running() for _ in range(10)]
                )

        assert start_calls == 1, f"Expected 1 start() call, got {start_calls}"
        assert all(r is True for r in results)

    # Coroutines that waited on the lock return _last_restart_ok without attempting
    # their own restart — verified here with a restart that returns False.
    @pytest.mark.asyncio
    async def test_queued_coroutines_return_restart_result(self):
        mgr = self._manager()

        async def slow_start():
            await asyncio.sleep(0)
            return False  # restart failed

        with patch.object(mgr, "_is_healthy", AsyncMock(return_value=False)):
            with patch.object(mgr, "start", side_effect=slow_start):
                results = await asyncio.gather(
                    *[mgr.ensure_running() for _ in range(5)]
                )

        assert all(r is False for r in results)
        assert mgr._restart_generation == 1

    @pytest.mark.asyncio
    async def test_externally_managed_does_not_restart(self):
        mgr = self._manager()
        mgr._externally_managed = True
        with patch.object(mgr, "_is_healthy", AsyncMock(return_value=False)):
            with patch.object(mgr, "start", AsyncMock()) as mock_start:
                result = await mgr.ensure_running()

        assert result is False
        mock_start.assert_not_called()
        assert mgr._restart_generation == 0
