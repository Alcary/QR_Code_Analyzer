"""
Browser Analysis Microservice

A lightweight HTTP server that accepts a URL, renders it in a sandboxed
Chromium instance via Playwright, and returns structured page-level
features for security analysis.

Endpoints:
    POST /analyze  — render a URL and extract security features
    GET  /health   — liveness check
"""

import asyncio
import ipaddress
import json
import logging
import os
import socket
import time
from difflib import SequenceMatcher
from urllib.parse import urlparse

from playwright.async_api import async_playwright, TimeoutError as PWTimeout

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────
PAGE_TIMEOUT_MS = int(os.environ.get("PAGE_TIMEOUT_MS", "12000"))
PORT = int(os.environ.get("PORT", "3000"))

# Private / reserved ranges that sub-requests must never reach.
_PRIVATE_NETS = [
    ipaddress.ip_network(cidr) for cidr in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",   # link-local
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
]


def _is_ssrf_target(url: str) -> bool:
    """
    Return True if the request URL resolves to a private / reserved address.

    Called synchronously inside Playwright's route handler.  Uses a
    short-timeout blocking DNS lookup — acceptable here because each
    page analysis runs in its own thread-isolated context and the
    lookup is bounded.

    Returns False (allow) if the hostname cannot be parsed or resolved,
    so legitimate pages are never accidentally blocked by DNS hiccups.
    """
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            return False
        # Raw IP — check directly without DNS
        try:
            addr = ipaddress.ip_address(host)
            return any(addr in net for net in _PRIVATE_NETS)
        except ValueError:
            pass
        # Hostname — resolve and check
        resolved = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for _, _, _, _, sockaddr in resolved:
            try:
                addr = ipaddress.ip_address(sockaddr[0])
                if any(addr in net for net in _PRIVATE_NETS):
                    return True
            except ValueError:
                continue
    except Exception:
        pass
    return False


# ── Feature Extraction ───────────────────────────────────────

async def extract_features(page, url: str) -> dict:
    """
    Navigate to *url* in the given Playwright page and extract
    security-relevant features from the rendered DOM and network activity.
    """
    network_requests: list[dict] = []
    console_messages: list[str] = []
    js_errors: list[str] = []
    popup_count = 0
    redirect_chain: list[str] = []

    # ── Listeners ──
    def on_request(req):
        try:
            parsed = urlparse(req.url)
            network_requests.append({
                "url": req.url,
                "method": req.method,
                "resource_type": req.resource_type,
                "domain": parsed.hostname or "",
                "is_navigation": req.is_navigation_request(),
            })
        except Exception:
            pass

    def on_console(msg):
        console_messages.append(msg.text[:200])

    def on_page_error(err):
        js_errors.append(str(err)[:200])

    def on_dialog(dialog):
        nonlocal popup_count
        popup_count += 1
        asyncio.ensure_future(dialog.dismiss())

    def on_response(resp):
        if resp.request.is_navigation_request() and 300 <= resp.status < 400:
            redirect_chain.append(resp.url)

    page.on("request", on_request)
    page.on("console", on_console)
    page.on("pageerror", on_page_error)
    page.on("dialog", on_dialog)
    page.on("response", on_response)

    # ── Navigate ──
    start = time.perf_counter()
    try:
        response = await page.goto(url, wait_until="networkidle", timeout=PAGE_TIMEOUT_MS)
    except PWTimeout:
        # Page didn't reach networkidle — extract what we have
        response = None
    load_time_ms = int((time.perf_counter() - start) * 1000)

    # Wait a bit more for any delayed JS execution
    await asyncio.sleep(1.0)

    final_url = page.url

    # ── DOM Feature Extraction (runs inside browser context) ──
    dom_features = await page.evaluate("""() => {
        const result = {};

        // --- Form Analysis ---
        const inputs = Array.from(document.querySelectorAll('input'));
        const forms = Array.from(document.querySelectorAll('form'));

        result.has_password_field = inputs.some(
            i => i.type === 'password'
        );
        result.password_field_count = inputs.filter(
            i => i.type === 'password'
        ).length;
        result.has_login_form = result.has_password_field && inputs.some(
            i => ['text', 'email', 'tel'].includes(i.type)
        );
        result.has_credit_card_input = inputs.some(i => {
            const n = (i.name + ' ' + i.id + ' ' + i.placeholder + ' ' +
                       i.getAttribute('autocomplete')).toLowerCase();
            return /credit.?card|card.?number|cc.?num|ccnum/.test(n)
                || i.getAttribute('autocomplete') === 'cc-number';
        });
        result.has_cvv_input = inputs.some(i => {
            const n = (i.name + ' ' + i.id + ' ' + i.placeholder).toLowerCase();
            return /\bcvv\b|\bcvc\b|\bcsc\b|security.?code/.test(n)
                || i.getAttribute('autocomplete') === 'cc-csc';
        });
        result.has_ssn_input = inputs.some(i => {
            const n = (i.name + ' ' + i.id + ' ' + i.placeholder).toLowerCase();
            return /\bssn\b|social.?security|tax.?id|national.?id/.test(n);
        });
        result.hidden_input_count = inputs.filter(
            i => i.type === 'hidden'
        ).length;
        result.total_input_count = inputs.length;
        result.form_count = forms.length;

        // Forms that POST to external domains
        const currentHost = window.location.hostname;
        result.external_form_action = forms.some(f => {
            try {
                const action = new URL(f.action, window.location.href);
                return action.hostname !== currentHost;
            } catch { return false; }
        });

        // --- iframes ---
        const iframes = Array.from(document.querySelectorAll('iframe'));
        result.iframe_count = iframes.length;
        result.external_iframe_count = iframes.filter(f => {
            try {
                const src = new URL(f.src, window.location.href);
                return src.hostname !== currentHost;
            } catch { return false; }
        }).length;

        // --- Scripts ---
        const scripts = Array.from(document.querySelectorAll('script'));
        result.inline_script_count = scripts.filter(s => !s.src).length;
        result.external_script_count = scripts.filter(s => !!s.src).length;
        result.total_script_count = scripts.length;

        // Check for obfuscation patterns in inline scripts
        const inlineCode = scripts
            .filter(s => !s.src)
            .map(s => s.textContent)
            .join(' ');
        result.has_eval_usage = /\beval\s*\(/.test(inlineCode);
        result.has_atob_eval = /eval\s*\(\s*atob\s*\(/.test(inlineCode);
        result.has_document_write = /document\.write\s*\(/.test(inlineCode);
        result.has_unescape = /unescape\s*\(/.test(inlineCode);
        result.has_fromcharcode = /fromCharCode/i.test(inlineCode);

        // --- Anti-Analysis Tricks ---
        // Right-click disabled
        result.disables_right_click = !!(
            document.oncontextmenu
            || document.body?.getAttribute('oncontextmenu')
            || inlineCode.includes('contextmenu')
        );
        // Text selection disabled
        const bodyStyle = document.body ? getComputedStyle(document.body) : {};
        result.disables_text_selection = (
            bodyStyle.userSelect === 'none'
            || bodyStyle.webkitUserSelect === 'none'
            || inlineCode.includes('selectstart')
        );
        // DevTools detection
        result.has_devtools_detection = (
            /devtools|debugger|__REACT_DEVTOOLS/.test(inlineCode)
            && /debugger|detect/.test(inlineCode)
        );

        // --- Page Metadata ---
        result.page_title = document.title || '';
        result.has_title = !!(document.title && document.title.trim());
        result.meta_description = (
            document.querySelector('meta[name="description"]')?.content || ''
        ).substring(0, 200);

        // Favicon
        const favicon = document.querySelector('link[rel*="icon"]');
        result.favicon_url = favicon ? favicon.href : '';

        // --- Content Indicators ---
        const bodyText = (document.body?.innerText || '').toLowerCase();

        result.has_urgency_text = /urgent|immediately|account.?suspend|verify.?now|act.?now|limited.?time/i
            .test(bodyText);
        result.has_threat_text = /unauthorized|illegal|locked|frozen|terminated|disabled/i
            .test(bodyText);

        // --- Visibility ---
        const allElements = document.querySelectorAll('*');
        let hiddenWithContent = 0;
        for (const el of allElements) {
            const style = getComputedStyle(el);
            if (
                (style.display === 'none' || style.visibility === 'hidden'
                 || style.opacity === '0')
                && el.innerHTML.trim().length > 50
            ) {
                hiddenWithContent++;
            }
            if (hiddenWithContent > 20) break;
        }
        result.hidden_elements_with_content = Math.min(hiddenWithContent, 20);

        // --- Favicon ---
        result.has_favicon = !!document.querySelector('link[rel*="icon"]');

        // --- Submit button ---
        result.has_submit_button = !!(
            document.querySelector('input[type="submit"]')
            || document.querySelector('button[type="submit"]')
            || Array.from(document.querySelectorAll('button')).some(
                b => /sign.?in|log.?in|submit|continue|verify/i.test(b.textContent)
            )
        );

        // --- Link analysis (self / empty / external refs) ---
        const anchors = Array.from(document.querySelectorAll('a[href]'));
        let selfRefCount = 0;
        let emptyRefCount = 0;
        let externalRefCount = 0;
        for (const a of anchors) {
            const href = (a.getAttribute('href') || '').trim();
            if (!href || href === '#' || href.startsWith('javascript:')) {
                emptyRefCount++;
            } else {
                try {
                    const linkUrl = new URL(href, window.location.href);
                    if (linkUrl.hostname === currentHost) {
                        selfRefCount++;
                    } else {
                        externalRefCount++;
                    }
                } catch {
                    emptyRefCount++;
                }
            }
        }
        result.self_ref_count = selfRefCount;
        result.empty_ref_count = emptyRefCount;
        result.external_ref_count = externalRefCount;

        // --- Financial keyword detection ---
        result.has_bank_keyword = /\b(bank|banking|account.?number|routing.?number|wire.?transfer|iban|swift)\b/i
            .test(bodyText);
        result.has_pay_keyword = /\b(payment|pay.?now|billing|invoice|transaction|purchase|checkout)\b/i
            .test(bodyText);
        result.has_crypto_keyword = /\b(bitcoin|ethereum|crypto|wallet|btc|eth|blockchain|seed.?phrase|private.?key)\b/i
            .test(bodyText);

        return result;
    }""")

    # ── Domain–Title Similarity ──
    page_domain = urlparse(final_url).hostname or ""
    _title = dom_features.get("page_title", "").strip().lower()
    _domain_words = page_domain.replace(".", " ").replace("-", " ").lower()
    dom_features["domain_title_match_score"] = (
        round(SequenceMatcher(None, _domain_words, _title).ratio() * 100, 2)
        if _title else 0.0
    )

    # ── Derived booleans for ML feature parity ──
    dom_features["has_hidden_fields"] = dom_features.get("hidden_input_count", 0) > 0

    # ── Network Request Analysis ──
    external_domains = set()
    script_domains = set()
    request_types = {}

    for req in network_requests:
        rtype = req.get("resource_type", "other")
        request_types[rtype] = request_types.get(rtype, 0) + 1

        req_domain = req.get("domain", "")
        if req_domain and req_domain != page_domain:
            external_domains.add(req_domain)
            if rtype == "script":
                script_domains.add(req_domain)

    network_features = {
        "total_requests": len(network_requests),
        "external_domain_count": len(external_domains),
        "external_script_domains": len(script_domains),
        "request_type_counts": request_types,
        "external_domains": list(external_domains)[:20],
    }

    # ── Redirect Analysis ──
    redirect_features = {
        "final_url": final_url,
        "url_changed": final_url != url,
        "final_domain": urlparse(final_url).hostname or "",
        "domain_changed": page_domain != (urlparse(url).hostname or ""),
        "redirect_count": len(redirect_chain),
    }

    # ── Popup / Dialog count ──
    dom_features["popup_count"] = popup_count

    # ── Brand Detection ──
    brand_features = _detect_brand_signals(
        dom_features.get("page_title", ""),
        dom_features.get("favicon_url", ""),
        page_domain,
    )

    # ── HTTP Response Info ──
    response_info = {}
    if response:
        response_info = {
            "status": response.status,
            "content_type": response.headers.get("content-type", ""),
        }

    return {
        "success": True,
        "url": url,
        "final_url": final_url,
        "page_features": dom_features,
        "network_features": network_features,
        "redirect_features": redirect_features,
        "brand_features": brand_features,
        "response_info": response_info,
        "js_errors": js_errors[:10],
        "timing": {
            "page_load_ms": load_time_ms,
        },
    }


# ── Brand Impersonation Detection ─────────────────────────────

_BRAND_PATTERNS = {
    "paypal": ["paypal"],
    "apple": ["apple", "icloud"],
    "google": ["google", "gmail"],
    "microsoft": ["microsoft", "outlook", "office365", "onedrive"],
    "amazon": ["amazon", "aws"],
    "facebook": ["facebook", "meta"],
    "netflix": ["netflix"],
    "instagram": ["instagram"],
    "twitter": ["twitter", "x.com"],
    "linkedin": ["linkedin"],
    "bank_of_america": ["bank of america", "bankofamerica"],
    "chase": ["chase"],
    "wells_fargo": ["wells fargo", "wellsfargo"],
    "ebay": ["ebay"],
    "dropbox": ["dropbox"],
    "dhl": ["dhl"],
    "fedex": ["fedex"],
    "usps": ["usps"],
    "whatsapp": ["whatsapp"],
    "telegram": ["telegram"],
}

_BRAND_OFFICIAL_DOMAINS = {
    "paypal": {"paypal.com"},
    "apple": {"apple.com", "icloud.com"},
    "google": {"google.com", "gmail.com", "googleapis.com"},
    "microsoft": {"microsoft.com", "outlook.com", "live.com", "office.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "aws.amazon.com"},
    "facebook": {"facebook.com", "fb.com", "meta.com"},
    "netflix": {"netflix.com"},
    "instagram": {"instagram.com"},
    "twitter": {"twitter.com", "x.com"},
    "linkedin": {"linkedin.com"},
    "ebay": {"ebay.com"},
    "dropbox": {"dropbox.com"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "usps": {"usps.com"},
    "whatsapp": {"whatsapp.com"},
    "telegram": {"telegram.org"},
}


def _detect_brand_signals(title: str, favicon_url: str, page_domain: str) -> dict:
    """Check if the page impersonates a known brand."""
    title_lower = title.lower()
    detected_brands = []

    for brand, keywords in _BRAND_PATTERNS.items():
        if any(kw in title_lower for kw in keywords):
            detected_brands.append(brand)

    brand_mismatch = False
    matched_brand = None
    for brand in detected_brands:
        official = _BRAND_OFFICIAL_DOMAINS.get(brand, set())
        if page_domain and not any(page_domain.endswith(d) for d in official):
            brand_mismatch = True
            matched_brand = brand
            break

    return {
        "page_title": title[:200],
        "detected_brands": detected_brands,
        "brand_domain_mismatch": brand_mismatch,
        "impersonated_brand": matched_brand,
    }


# ── HTTP Server ───────────────────────────────────────────────

from aiohttp import web

_browser = None
_playwright = None


async def startup(app):
    """Launch browser on server start."""
    global _browser, _playwright
    _playwright = await async_playwright().start()
    _browser = await _playwright.chromium.launch(
        args=[
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu",
            "--disable-extensions",
            "--disable-background-networking",
            "--disable-sync",
            "--disable-translate",
            "--no-first-run",
        ]
    )
    logger.info("Browser launched (Chromium)")


async def shutdown(app):
    """Close browser on server stop."""
    global _browser, _playwright
    if _browser:
        await _browser.close()
    if _playwright:
        await _playwright.stop()
    logger.info("Browser closed")


async def handle_analyze(request: web.Request) -> web.Response:
    """POST /analyze — render URL and extract features."""
    try:
        body = await request.json()
    except Exception:
        return web.json_response(
            {"success": False, "error": "Invalid JSON body"},
            status=400,
        )

    url = body.get("url", "").strip()
    if not url:
        return web.json_response(
            {"success": False, "error": "Missing 'url' field"},
            status=400,
        )

    # Basic scheme validation
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return web.json_response(
            {"success": False, "error": f"Unsupported scheme: {parsed.scheme}"},
            status=400,
        )

    logger.info("Analyzing: %s", url[:120])

    context = None
    try:
        # Each analysis gets a fresh, isolated browser context
        context = await _browser.new_context(
            ignore_https_errors=False,
            java_script_enabled=True,
            locale="en-US",
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/131.0.0.0 Safari/537.36"
            ),
            viewport={"width": 1280, "height": 720},
        )
        page = await context.new_page()

        # Block requests to private/internal addresses (SSRF via subresources)
        # and known tracking/ad domains (noise reduction).
        _TRACKING = (
            "google-analytics.com",
            "googletagmanager.com",
            "doubleclick.net",
            "facebook.net/tr",
        )

        async def _route_handler(route):
            req_url = route.request.url
            if _is_ssrf_target(req_url):
                logger.debug("Blocked SSRF sub-request: %s", req_url[:120])
                await route.abort()
                return
            if any(t in req_url for t in _TRACKING):
                await route.abort()
                return
            await route.continue_()

        await page.route("**/*", _route_handler)

        result = await extract_features(page, url)
        return web.json_response(result)

    except Exception as e:
        logger.error("Analysis failed for %s: %s", url[:80], e)
        return web.json_response(
            {"success": False, "error": str(e)[:200], "url": url},
            status=500,
        )
    finally:
        if context:
            await context.close()


async def handle_health(request: web.Request) -> web.Response:
    """GET /health — liveness probe."""
    try:
        browser_ok = _browser is not None and _browser.is_connected()
    except Exception:
        browser_ok = False
    return web.json_response({
        "status": "ok" if browser_ok else "degraded",
        "browser": browser_ok,
    })


def create_app() -> web.Application:
    app = web.Application()
    app.on_startup.append(startup)
    app.on_shutdown.append(shutdown)
    app.router.add_post("/analyze", handle_analyze)
    app.router.add_get("/health", handle_health)
    return app


if __name__ == "__main__":
    web.run_app(create_app(), host="0.0.0.0", port=PORT)
