"""
Network Intelligence Module

Runs async inspections in parallel:
1. DNS  — resolution, TTL, MX/NS records, suspicious nameservers
2. SSL  — certificate validity, age, issuer, expiry
3. HTTP — redirects, content analysis, scheme check
4. WHOIS — domain age, registrar
"""

import asyncio
import ipaddress
import re
import ssl
import socket
import logging
from datetime import datetime, timezone
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin

import aiohttp

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
# SSRF Protection — Block requests to private/reserved networks
# ═══════════════════════════════════════════════════════════════

# IP ranges that must never be fetched by the HTTP inspector.
# Prevents Server-Side Request Forgery (SSRF) attacks where a
# malicious QR code points to internal infrastructure.
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),         # "This" network
    ipaddress.ip_network("10.0.0.0/8"),         # RFC 1918 private
    ipaddress.ip_network("100.64.0.0/10"),      # Carrier-grade NAT
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local (AWS metadata: 169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918 private
    ipaddress.ip_network("192.0.0.0/24"),       # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918 private
    ipaddress.ip_network("198.18.0.0/15"),      # Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    # IPv6 equivalents
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("fc00::/7"),           # Unique local
    ipaddress.ip_network("fe80::/10"),          # Link-local
]


def _is_private_or_reserved(hostname: str) -> bool:
    """
    Resolve a hostname and check if any of its IPs fall in blocked ranges.

    Returns True if the target is a private/reserved address (SSRF risk).
    """
    try:
        # First check if the hostname itself is an IP literal
        try:
            addr = ipaddress.ip_address(hostname)
            return any(addr in net for net in _BLOCKED_NETWORKS)
        except ValueError:
            pass  # Not an IP literal — resolve via DNS

        # Resolve hostname → IPs and check each
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for family, _, _, _, sockaddr in infos:
            ip_str = sockaddr[0]
            try:
                addr = ipaddress.ip_address(ip_str)
                if any(addr in net for net in _BLOCKED_NETWORKS):
                    return True
            except ValueError:
                continue
        return False
    except (socket.gaierror, OSError):
        return False  # DNS failed — HTTP check will catch this separately


# ═══════════════════════════════════════════════════════════════
# Result Data Classes
# ═══════════════════════════════════════════════════════════════

@dataclass
class DNSResult:
    resolved: bool = False
    ttl: int | None = None
    flags: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class SSLResult:
    valid: bool = False
    issuer: str | None = None
    days_until_expiry: int | None = None
    cert_age_days: int | None = None
    is_new_cert: bool | None = None
    error: str | None = None


@dataclass
class HTTPResult:
    status_code: int | None = None
    final_url: str | None = None
    redirect_count: int = 0
    redirect_domain_mismatch: bool = False
    content_flags: list[str] = field(default_factory=list)
    scheme_warning: bool = False
    server: str | None = None
    error: str | None = None


@dataclass
class WHOISResult:
    age_days: int | None = None
    creation_date: str | None = None
    registrar: str | None = None
    is_new_domain: bool | None = None
    error: str | None = None


@dataclass
class NetworkResult:
    dns: DNSResult = field(default_factory=DNSResult)
    ssl: SSLResult = field(default_factory=SSLResult)
    http: HTTPResult = field(default_factory=HTTPResult)
    whois: WHOISResult = field(default_factory=WHOISResult)


# ═══════════════════════════════════════════════════════════════
# Network Inspector
# ═══════════════════════════════════════════════════════════════

class NetworkInspector:
    """Runs all network-level inspections concurrently."""

    def __init__(self, http_timeout: float = 8.0, whois_timeout: float = 10.0):
        self.http_timeout = http_timeout
        self.whois_timeout = whois_timeout

    async def inspect_all(
        self, url: str, domain: str, registered_domain: str
    ) -> NetworkResult:
        """Run DNS, SSL, HTTP, and WHOIS inspections in parallel."""
        tasks = [
            self._check_dns(domain, registered_domain),
            self._check_ssl(domain),
            self._check_http(url, registered_domain),
            self._check_whois(registered_domain),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        net = NetworkResult()
        net.dns = results[0] if isinstance(results[0], DNSResult) else DNSResult(error=str(results[0]))
        net.ssl = results[1] if isinstance(results[1], SSLResult) else SSLResult(error=str(results[1]))
        net.http = results[2] if isinstance(results[2], HTTPResult) else HTTPResult(error=str(results[2]))
        net.whois = results[3] if isinstance(results[3], WHOISResult) else WHOISResult(error=str(results[3]))
        return net

    # ── DNS ────────────────────────────────────────────────────

    async def _check_dns(self, domain: str, registered_domain: str = "") -> DNSResult:
        """DNS resolution + TTL + MX/NS analysis."""
        result = DNSResult()
        loop = asyncio.get_running_loop()
        # MX records live on the apex/registered domain, not subdomains
        mx_domain = registered_domain or domain

        try:
            import dns.resolver

            # A record
            try:
                answers = await loop.run_in_executor(
                    None, lambda: dns.resolver.resolve(domain, "A")
                )
                result.resolved = True
                result.ttl = answers.rrset.ttl
                # Use low threshold (≤15s) — dns.resolver returns the
                # *remaining* TTL from the resolver cache, not the
                # original.  A 300s record cached 290s ago shows TTL=10.
                # Threshold of 5 targets true fast-flux (TTL 0-3) only,
                # avoiding false positives on CDN-cached domains.
                if result.ttl is not None and result.ttl < 5:
                    result.flags.append("very_low_ttl")
            except dns.resolver.NXDOMAIN:
                result.error = "domain_not_found"
                return result
            except dns.resolver.NoNameservers:
                result.error = "no_nameservers"
                return result
            except dns.resolver.NoAnswer:
                result.flags.append("no_a_record")
            except Exception:
                pass

            # MX records — check on registered/apex domain, not subdomains
            try:
                await loop.run_in_executor(
                    None, lambda: dns.resolver.resolve(mx_domain, "MX")
                )
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                result.flags.append("no_mx_records")
            except Exception:
                pass

            # NS records
            try:
                ns_answers = await loop.run_in_executor(
                    None, lambda: dns.resolver.resolve(domain, "NS")
                )
                ns_names = [str(r).lower() for r in ns_answers]
                suspicious_ns = ["freedns", "afraid.org", "cloudns", "he.net"]
                if any(s in " ".join(ns_names) for s in suspicious_ns):
                    result.flags.append("suspicious_nameserver")
            except Exception:
                pass

        except ImportError:
            # Fallback: basic socket resolution
            try:
                await loop.run_in_executor(None, socket.gethostbyname, domain)
                result.resolved = True
            except socket.gaierror:
                result.error = "domain_not_found"

        return result

    # ── SSL ────────────────────────────────────────────────────

    async def _check_ssl(self, domain: str) -> SSLResult:
        """SSL certificate analysis — validity, age, issuer, expiry."""
        result = SSLResult()
        loop = asyncio.get_running_loop()

        def _get_cert():
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as conn:
                conn.settimeout(5)
                conn.connect((domain, 443))
                return conn.getpeercert()

        try:
            cert = await loop.run_in_executor(None, _get_cert)
            if not cert:
                result.error = "empty_cert"
                return result

            result.valid = True

            # Issuer
            for item in cert.get("issuer", ()):
                for key, value in item:
                    if key == "organizationName":
                        result.issuer = value

            now = datetime.now(timezone.utc)

            # Expiry
            not_after_str = cert.get("notAfter", "")
            if not_after_str:
                not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                result.days_until_expiry = (not_after - now).days

            # Age
            not_before_str = cert.get("notBefore", "")
            if not_before_str:
                not_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                result.cert_age_days = (now - not_before).days
                result.is_new_cert = result.cert_age_days < 7

        except ssl.SSLCertVerificationError:
            result.error = "ssl_verification_failed"
        except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError):
            result.error = "ssl_connection_failed"
        except Exception as e:
            result.error = str(e)[:120]

        return result

    # ── HTTP ───────────────────────────────────────────────────

    async def _check_http(self, url: str, registered_domain: str) -> HTTPResult:
        """
        Follow redirects manually, inspecting each hop for SSRF.

        Security properties enforced:
        - TLS certificates ARE verified (ssl=True, the aiohttp default).
          Passing ssl=False would nullify transport security for all HTTPS
          inspection requests — we never do that.
        - Every redirect destination is SSRF-checked before the request is
          made.  aiohttp's allow_redirects=True bypasses per-hop checks, so
          we follow redirects manually with allow_redirects=False.
        - SSRF check failures are treated as blocking errors, not silently
          ignored — a failed check is not a safe condition.
        - Response body is capped at MAX_RESPONSE_BYTES to prevent memory
          exhaustion from slow-read / large-body attacks.
        - Hard redirect cap (MAX_REDIRECTS) raises an error rather than
          following indefinitely.
        """
        MAX_REDIRECTS = 10
        MAX_RESPONSE_BYTES = 50_000  # 50 KB cap on content inspection

        result = HTTPResult()
        loop = asyncio.get_running_loop()

        # ── SSRF check on the initial URL ─────────────────────
        try:
            initial_host = urlparse(url).hostname or ""
            if not initial_host:
                result.error = "invalid_url"
                return result
            is_private = await loop.run_in_executor(
                None, _is_private_or_reserved, initial_host
            )
            if is_private:
                logger.warning(
                    "SSRF blocked (initial): %s resolves to private/reserved IP",
                    initial_host,
                )
                result.error = "ssrf_blocked"
                return result
        except Exception as exc:
            # A failed SSRF check is NOT safe to ignore — block the request.
            logger.warning("SSRF pre-check failed for %s: %s", url, exc)
            result.error = "ssrf_check_failed"
            return result

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/131.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

        try:
            timeout = aiohttp.ClientTimeout(total=self.http_timeout)
            # ssl=True (the aiohttp default) — TLS certificates are verified.
            # We do NOT pass ssl=False.
            async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
                current_url = url
                redirect_count = 0

                while True:
                    # ── Per-hop SSRF check (skip for hop 0: already checked) ──
                    if redirect_count > 0:
                        hop_host = urlparse(current_url).hostname or ""
                        try:
                            is_private = await loop.run_in_executor(
                                None, _is_private_or_reserved, hop_host
                            )
                            if is_private:
                                logger.warning(
                                    "SSRF blocked on redirect hop %d: %s",
                                    redirect_count,
                                    hop_host,
                                )
                                result.error = "ssrf_blocked"
                                result.redirect_count = redirect_count
                                return result
                        except Exception as exc:
                            logger.warning(
                                "SSRF per-hop check failed for %s: %s", hop_host, exc
                            )
                            result.error = "ssrf_check_failed"
                            result.redirect_count = redirect_count
                            return result

                    async with session.get(
                        current_url,
                        allow_redirects=False,  # we follow manually for per-hop SSRF
                        ssl=True,               # verify TLS certificates
                    ) as resp:
                        if resp.status in (301, 302, 303, 307, 308):
                            location = resp.headers.get("Location", "").strip()
                            if not location:
                                # Redirect with no Location — treat as terminal
                                result.status_code = resp.status
                                result.final_url = current_url
                                result.redirect_count = redirect_count
                                break

                            redirect_count += 1
                            if redirect_count > MAX_REDIRECTS:
                                result.error = "too_many_redirects"
                                result.redirect_count = redirect_count
                                break

                            # Resolve relative redirects against the current URL
                            current_url = urljoin(current_url, location)
                            continue  # check SSRF on next hop then follow

                        # ── Non-redirect: process the final response ──────
                        result.status_code = resp.status
                        result.final_url = str(resp.url)
                        result.redirect_count = redirect_count
                        result.server = resp.headers.get("Server")

                        if result.final_url.startswith("http://"):
                            result.scheme_warning = True

                        if redirect_count > 0 and registered_domain:
                            from app.services.domain_reputation import get_registered_domain
                            final_reg = get_registered_domain(result.final_url)
                            if final_reg != registered_domain:
                                result.redirect_domain_mismatch = True

                        # Content inspection — HTML only, body capped at MAX_RESPONSE_BYTES
                        ctype = resp.headers.get("Content-Type", "").lower()
                        if resp.status == 200 and "text/html" in ctype:
                            try:
                                raw = await resp.content.read(MAX_RESPONSE_BYTES)
                                text = raw.decode("utf-8", errors="replace").lower()

                                if 'type="password"' in text or 'name="password"' in text:
                                    result.content_flags.append("password_field")
                                if any(w in text for w in ("credit card", "billing address", "cvv")):
                                    result.content_flags.append("billing_info_request")
                                if re.search(r'\bssn\b|\bsocial security\b', text):
                                    result.content_flags.append("sensitive_id_request")
                                if "geolocation.getcurrentposition" in text:
                                    result.content_flags.append("geolocation_tracking")
                                if text.count("<iframe") > 3:
                                    result.content_flags.append("excessive_iframes")
                                if "eval(atob(" in text or "eval(unescape(" in text:
                                    result.content_flags.append("obfuscated_javascript")
                            except Exception:
                                pass

                        break  # inspection complete

        except aiohttp.ClientConnectorSSLError as exc:
            # TLS certificate verification failed — the site has an invalid cert.
            # This is distinct from site_unreachable and informs the SSL risk score.
            logger.debug("SSL verification failed for %s: %s", url, exc)
            result.error = "ssl_verification_failed"
        except aiohttp.ClientError:
            result.error = "site_unreachable"
        except asyncio.TimeoutError:
            result.error = "timeout"
        except Exception as e:
            result.error = str(e)[:120]

        return result

    # ── WHOIS ──────────────────────────────────────────────────

    async def _check_whois(self, domain: str) -> WHOISResult:
        """WHOIS domain age lookup."""
        result = WHOISResult()
        try:
            import whois
        except ImportError:
            result.error = "whois_not_installed"
            return result

        try:
            loop = asyncio.get_running_loop()
            w = await asyncio.wait_for(
                loop.run_in_executor(None, whois.whois, domain),
                timeout=self.whois_timeout,
            )

            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]

            if creation:
                if creation.tzinfo is None:
                    creation = creation.replace(tzinfo=timezone.utc)
                result.creation_date = str(creation)
                result.age_days = (datetime.now(timezone.utc) - creation).days
                result.is_new_domain = result.age_days < 30

            result.registrar = w.registrar

        except asyncio.TimeoutError:
            result.error = "whois_timeout"
        except asyncio.CancelledError:
            result.error = "whois_cancelled"
        except Exception as e:
            result.error = str(e)[:120]

        return result


# Singleton
network_inspector = NetworkInspector()
