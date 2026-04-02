"""
Browser Analysis Client

Calls the containerized browser microservice to render a page and extract
security-relevant features.  Converts raw browser features into structured
risk signals that the analyzer pipeline can consume.

Container lifecycle is managed automatically:
- On API startup  → build image (if needed) and start the container
- Before each request → health-check; if the container is dead, restart it
- On API shutdown → stop and remove the container
"""

import asyncio
import logging
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import aiohttp

from app.core.config import settings

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
# Result Data Class
# ═══════════════════════════════════════════════════════════════

@dataclass
class BrowserResult:
    """Structured output from browser-based page analysis."""
    success: bool = False
    error: str | None = None

    # Page features
    has_password_field: bool = False
    password_field_count: int = 0
    has_login_form: bool = False
    has_credit_card_input: bool = False
    has_cvv_input: bool = False
    has_ssn_input: bool = False
    hidden_input_count: int = 0
    total_input_count: int = 0
    form_count: int = 0
    external_form_action: bool = False

    # iframes
    iframe_count: int = 0
    external_iframe_count: int = 0

    # Scripts
    inline_script_count: int = 0
    external_script_count: int = 0
    total_script_count: int = 0
    has_eval_usage: bool = False
    has_atob_eval: bool = False
    has_document_write: bool = False
    has_unescape: bool = False
    has_fromcharcode: bool = False

    # Anti-analysis
    disables_right_click: bool = False
    disables_text_selection: bool = False
    has_devtools_detection: bool = False

    # Content
    has_urgency_text: bool = False
    has_threat_text: bool = False
    hidden_elements_with_content: int = 0

    # Network
    total_requests: int = 0
    external_domain_count: int = 0
    external_script_domains: int = 0

    # Redirect
    final_url: str | None = None
    url_changed: bool = False
    domain_changed: bool = False

    # Brand
    page_title: str = ""
    detected_brands: list[str] = field(default_factory=list)
    brand_domain_mismatch: bool = False
    impersonated_brand: str | None = None

    # Timing
    page_load_ms: int = 0


# ═══════════════════════════════════════════════════════════════
# Docker Container Manager
# ═══════════════════════════════════════════════════════════════

CONTAINER_NAME = "qr-browser-service"
IMAGE_NAME = "qr-browser-service:latest"


class ContainerManager:
    """
    Manages the browser service Docker container lifecycle.

    Uses the Docker SDK (docker-py) to build, start, health-check,
    and restart the container automatically.
    """

    def __init__(self, container_port: int = 3000, host_port: int | None = None):
        self._client = None
        self._container = None
        self.container_port = container_port
        # Derive host port from BROWSER_SERVICE_URL so it matches config
        if host_port is None:
            try:
                parsed = urlparse(settings.BROWSER_SERVICE_URL)
                self.host_port = parsed.port or container_port
            except Exception:
                self.host_port = container_port
        else:
            self.host_port = host_port
        # Lock: only one restart attempt at a time
        self._restart_lock = asyncio.Lock()

    def _get_client(self):
        """Lazy-init Docker client."""
        if self._client is None:
            try:
                import docker
                self._client = docker.from_env()
                self._client.ping()
            except Exception as e:
                logger.warning("Docker is not available: %s", e)
                self._client = None
        return self._client

    def _find_browser_service_dir(self) -> Path | None:
        """Locate the browser-service directory relative to the server root."""
        candidates = [
            Path(__file__).resolve().parent.parent.parent / "browser-service",
            Path.cwd() / "browser-service",
        ]
        for p in candidates:
            if (p / "Dockerfile").exists():
                return p
        return None

    async def start(self) -> bool:
        """
        Ensure the browser container is running.

        Build the image if needed, then start (or restart) the container.
        Returns True if the container is running after this call.
        """
        client = self._get_client()
        if client is None:
            logger.warning("Docker not available — browser analysis will use external service or be skipped")
            return False

        loop = asyncio.get_running_loop()

        # Check if container already exists and is running
        try:
            existing = await loop.run_in_executor(
                None, lambda: client.containers.get(CONTAINER_NAME)
            )
            if existing.status == "running":
                logger.info("Browser container '%s' is already running", CONTAINER_NAME)
                self._container = existing
                return True
            # Exists but not running — remove and recreate
            logger.info("Browser container exists but status=%s, removing...", existing.status)
            await loop.run_in_executor(None, lambda: existing.remove(force=True))
        except Exception:
            pass  # Container doesn't exist yet

        # Build image
        build_dir = self._find_browser_service_dir()
        if build_dir is None:
            logger.error("Cannot find browser-service/ directory — skipping container start")
            return False

        logger.info("Building browser service image from %s ...", build_dir)
        try:
            await loop.run_in_executor(
                None,
                lambda: client.images.build(
                    path=str(build_dir),
                    tag=IMAGE_NAME,
                    rm=True,
                )
            )
            logger.info("Image '%s' built successfully", IMAGE_NAME)
        except Exception as e:
            logger.error("Failed to build browser image: %s", e)
            return False

        # Start container
        try:
            self._container = await loop.run_in_executor(
                None,
                lambda: client.containers.run(
                    IMAGE_NAME,
                    name=CONTAINER_NAME,
                    detach=True,
                    ports={f"{self.container_port}/tcp": self.host_port},
                    environment={
                        "PAGE_TIMEOUT_MS": str(settings.BROWSER_PAGE_TIMEOUT_MS),
                        "PORT": str(self.container_port),
                    },
                    mem_limit="1g",
                    cpu_quota=100000,  # 1 CPU
                    restart_policy={"Name": "unless-stopped"},
                )
            )
            logger.info("Browser container '%s' started on port %d", CONTAINER_NAME, self.host_port)
        except Exception as e:
            logger.error("Failed to start browser container: %s", e)
            return False

        # Wait for health check
        for attempt in range(10):
            await asyncio.sleep(2)
            if await self._is_healthy():
                logger.info("Browser container is healthy")
                return True
            logger.info("Waiting for browser container to become healthy (attempt %d/10)...", attempt + 1)

        logger.error("Browser container did not become healthy in time")
        return False

    async def stop(self) -> None:
        """Stop and remove the browser container."""
        client = self._get_client()
        if client is None:
            return

        loop = asyncio.get_running_loop()
        try:
            container = await loop.run_in_executor(
                None, lambda: client.containers.get(CONTAINER_NAME)
            )
            await loop.run_in_executor(
                None, lambda: container.stop(timeout=10)
            )
            await loop.run_in_executor(
                None, lambda: container.remove(force=True)
            )
            logger.info("Browser container '%s' stopped and removed", CONTAINER_NAME)
        except Exception as e:
            logger.debug("Container stop/remove: %s", e)

        self._container = None

    async def ensure_running(self) -> bool:
        """
        Check if the container is alive; restart it if not.
        Called before each analysis request.

        The restart lock ensures that if multiple requests find the container
        dead simultaneously, only one of them does the restart work. The
        others wait and then re-check rather than all trying to rebuild at once.
        """
        if await self._is_healthy():
            return True

        async with self._restart_lock:
            # Re-check inside the lock — another coroutine may have already
            # restarted the container while we were waiting to acquire it.
            if await self._is_healthy():
                return True
            logger.warning("Browser container is not healthy — restarting...")
            return await self.start()

    async def _is_healthy(self) -> bool:
        """Quick HTTP health check against the browser service."""
        try:
            timeout = aiohttp.ClientTimeout(total=3.0)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(
                    f"{settings.BROWSER_SERVICE_URL}/health"
                ) as resp:
                    return resp.status == 200
        except Exception:
            return False


# Singleton container manager
container_manager = ContainerManager()


# ═══════════════════════════════════════════════════════════════
# Browser Analyzer Client
# ═══════════════════════════════════════════════════════════════

class BrowserAnalyzer:
    """
    Client that calls the browser microservice and converts raw
    JSON features into a BrowserResult and risk factors.

    Automatically ensures the browser container is running before
    each analysis. If the container crashed, it restarts it.
    """

    def __init__(self, service_url: str, timeout: float = 15.0, max_concurrent: int = 5):
        self.service_url = service_url.rstrip("/")
        self.timeout = timeout
        # Semaphore: limits how many pages can be rendered at the same time.
        # Each browser context uses ~50-100 MB, so 5 concurrent renders fit
        # comfortably within the container's 1 GB memory limit.
        # Requests beyond this limit wait in a queue automatically.
        self._semaphore = asyncio.Semaphore(max_concurrent)

    async def analyze(self, url: str) -> BrowserResult:
        """
        Send a URL to the browser service for rendering and feature
        extraction.  Returns a BrowserResult even on failure (with
        success=False and an error message).

        Automatically restarts the container if it's not healthy.
        At most `max_concurrent` renders run simultaneously; others queue.
        """
        result = BrowserResult()

        # Ensure the browser container is alive before making the request
        if settings.BROWSER_ANALYSIS_ENABLED:
            container_ok = await container_manager.ensure_running()
            if not container_ok:
                result.error = "browser_container_unavailable"
                logger.warning("Browser container unavailable — skipping browser analysis")
                return result

        async with self._semaphore:
            return await self._do_analyze(url)

    async def _do_analyze(self, url: str) -> BrowserResult:
        """Inner analysis call — runs under the concurrency semaphore."""
        result = BrowserResult()

        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(
                    f"{self.service_url}/analyze",
                    json={"url": url},
                ) as resp:
                    if resp.status != 200:
                        body = await resp.text()
                        result.error = f"Browser service returned {resp.status}: {body[:200]}"
                        logger.warning("Browser service error: %s", result.error)
                        return result

                    data = await resp.json()

        except asyncio.TimeoutError:
            result.error = "browser_timeout"
            logger.warning("Browser analysis timed out for %s", url[:80])
            return result
        except aiohttp.ClientError as e:
            result.error = f"browser_unreachable: {e}"
            logger.warning("Browser service unreachable: %s", e)
            return result
        except Exception as e:
            result.error = f"browser_error: {e}"
            logger.error("Unexpected browser analysis error: %s", e)
            return result

        if not data.get("success"):
            result.error = data.get("error", "unknown_error")
            return result

        # ── Map JSON response to BrowserResult ──
        result.success = True
        _map_page_features(result, data.get("page_features", {}))
        _map_network_features(result, data.get("network_features", {}))
        _map_redirect_features(result, data.get("redirect_features", {}))
        _map_brand_features(result, data.get("brand_features", {}))
        result.page_load_ms = data.get("timing", {}).get("page_load_ms", 0)
        result.final_url = data.get("final_url")

        return result

    async def health_check(self) -> bool:
        """Check if the browser service is alive."""
        return await container_manager._is_healthy()

    def compute_risk_signals(self, result: BrowserResult) -> tuple[float, list[dict]]:
        """
        Convert a BrowserResult into a 0.0-1.0 risk score and a list
        of structured risk factors.

        Returns (risk_score, risk_factors).
        """
        if not result.success:
            return 0.0, []

        risk = 0.0
        factors: list[dict] = []

        def _rf(code: str, message: str, severity: str, evidence: str | None = None) -> dict:
            f: dict = {"code": code, "message": message, "severity": severity}
            if evidence is not None:
                f["evidence"] = evidence
            return f

        # ── Credential harvesting signals ──
        if result.has_login_form:
            risk += 0.05
            factors.append(_rf(
                "browser_login_form",
                "Page contains a login form (rendered)",
                "medium",
            ))

        if result.has_credit_card_input:
            risk += 0.15
            factors.append(_rf(
                "browser_credit_card_input",
                "Page requests credit card information",
                "high",
            ))

        if result.has_cvv_input:
            risk += 0.10
            factors.append(_rf(
                "browser_cvv_input",
                "Page requests CVV/security code",
                "high",
            ))

        if result.has_ssn_input:
            risk += 0.15
            factors.append(_rf(
                "browser_ssn_input",
                "Page requests Social Security / national ID",
                "critical",
            ))

        if result.external_form_action:
            risk += 0.12
            factors.append(_rf(
                "browser_external_form",
                "Form submits data to external domain",
                "high",
            ))

        # ── JavaScript obfuscation ──
        obfuscation_signals = sum([
            result.has_eval_usage,
            result.has_atob_eval,
            result.has_document_write,
            result.has_unescape,
            result.has_fromcharcode,
        ])
        if obfuscation_signals >= 2:
            risk += 0.15
            factors.append(_rf(
                "browser_js_obfuscation",
                f"Multiple JavaScript obfuscation techniques detected ({obfuscation_signals})",
                "high",
                evidence=str(obfuscation_signals),
            ))
        elif result.has_atob_eval:
            risk += 0.10
            factors.append(_rf(
                "browser_eval_atob",
                "JavaScript uses eval(atob()) — encoded code execution",
                "high",
            ))

        # ── Excessive external scripts ──
        if result.external_script_domains > 8:
            risk += 0.08
            factors.append(_rf(
                "browser_many_script_domains",
                f"Scripts loaded from {result.external_script_domains} external domains",
                "medium",
                evidence=str(result.external_script_domains),
            ))

        # ── Anti-analysis tricks ──
        if result.disables_right_click:
            risk += 0.08
            factors.append(_rf(
                "browser_no_right_click",
                "Page disables right-click (anti-inspection)",
                "medium",
            ))

        if result.disables_text_selection:
            risk += 0.05
            factors.append(_rf(
                "browser_no_text_select",
                "Page disables text selection",
                "low",
            ))

        if result.has_devtools_detection:
            risk += 0.10
            factors.append(_rf(
                "browser_devtools_detection",
                "Page attempts to detect developer tools",
                "high",
            ))

        # ── Brand impersonation ──
        if result.brand_domain_mismatch and result.impersonated_brand:
            risk += 0.20
            factors.append(_rf(
                "browser_brand_impersonation",
                f"Page impersonates {result.impersonated_brand} on unofficial domain",
                "critical",
                evidence=result.impersonated_brand,
            ))

        # ── Social engineering ──
        if result.has_urgency_text:
            risk += 0.08
            factors.append(_rf(
                "browser_urgency_language",
                "Page uses urgency/pressure language",
                "medium",
            ))

        if result.has_threat_text:
            risk += 0.08
            factors.append(_rf(
                "browser_threat_language",
                "Page uses threatening language (account suspended, etc.)",
                "medium",
            ))

        # ── Hidden content ──
        if result.hidden_elements_with_content > 5:
            risk += 0.06
            factors.append(_rf(
                "browser_hidden_content",
                f"Excessive hidden elements with content ({result.hidden_elements_with_content})",
                "medium",
                evidence=str(result.hidden_elements_with_content),
            ))

        # ── iframes ──
        if result.external_iframe_count > 2:
            risk += 0.08
            factors.append(_rf(
                "browser_external_iframes",
                f"Multiple external iframes ({result.external_iframe_count})",
                "medium",
                evidence=str(result.external_iframe_count),
            ))

        # ── JS redirect / domain change ──
        if result.domain_changed:
            risk += 0.05
            factors.append(_rf(
                "browser_js_redirect",
                f"Page redirected via JavaScript to different domain",
                "medium",
                evidence=result.final_url,
            ))

        return min(1.0, risk), factors


# ═══════════════════════════════════════════════════════════════
# Mapping helpers (raw JSON → BrowserResult fields)
# ═══════════════════════════════════════════════════════════════

def _map_page_features(result: BrowserResult, pf: dict) -> None:
    result.has_password_field = pf.get("has_password_field", False)
    result.password_field_count = pf.get("password_field_count", 0)
    result.has_login_form = pf.get("has_login_form", False)
    result.has_credit_card_input = pf.get("has_credit_card_input", False)
    result.has_cvv_input = pf.get("has_cvv_input", False)
    result.has_ssn_input = pf.get("has_ssn_input", False)
    result.hidden_input_count = pf.get("hidden_input_count", 0)
    result.total_input_count = pf.get("total_input_count", 0)
    result.form_count = pf.get("form_count", 0)
    result.external_form_action = pf.get("external_form_action", False)
    result.iframe_count = pf.get("iframe_count", 0)
    result.external_iframe_count = pf.get("external_iframe_count", 0)
    result.inline_script_count = pf.get("inline_script_count", 0)
    result.external_script_count = pf.get("external_script_count", 0)
    result.total_script_count = pf.get("total_script_count", 0)
    result.has_eval_usage = pf.get("has_eval_usage", False)
    result.has_atob_eval = pf.get("has_atob_eval", False)
    result.has_document_write = pf.get("has_document_write", False)
    result.has_unescape = pf.get("has_unescape", False)
    result.has_fromcharcode = pf.get("has_fromcharcode", False)
    result.disables_right_click = pf.get("disables_right_click", False)
    result.disables_text_selection = pf.get("disables_text_selection", False)
    result.has_devtools_detection = pf.get("has_devtools_detection", False)
    result.has_urgency_text = pf.get("has_urgency_text", False)
    result.has_threat_text = pf.get("has_threat_text", False)
    result.hidden_elements_with_content = pf.get("hidden_elements_with_content", 0)
    result.page_title = pf.get("page_title", "")


def _map_network_features(result: BrowserResult, nf: dict) -> None:
    result.total_requests = nf.get("total_requests", 0)
    result.external_domain_count = nf.get("external_domain_count", 0)
    result.external_script_domains = nf.get("external_script_domains", 0)


def _map_redirect_features(result: BrowserResult, rf: dict) -> None:
    result.url_changed = rf.get("url_changed", False)
    result.domain_changed = rf.get("domain_changed", False)
    if rf.get("final_url"):
        result.final_url = rf["final_url"]


def _map_brand_features(result: BrowserResult, bf: dict) -> None:
    result.detected_brands = bf.get("detected_brands", [])
    result.brand_domain_mismatch = bf.get("brand_domain_mismatch", False)
    result.impersonated_brand = bf.get("impersonated_brand")


# ═══════════════════════════════════════════════════════════════
# Singleton
# ═══════════════════════════════════════════════════════════════

browser_analyzer = BrowserAnalyzer(
    service_url=settings.BROWSER_SERVICE_URL,
    timeout=settings.BROWSER_TIMEOUT,
    max_concurrent=settings.BROWSER_MAX_CONCURRENT,
)
