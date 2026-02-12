"""
Network Intelligence Module

Runs async inspections in parallel:
1. DNS  — resolution, TTL, MX/NS records, suspicious nameservers
2. SSL  — certificate validity, age, issuer, expiry
3. HTTP — redirects, content analysis, scheme check
4. WHOIS — domain age, registrar
"""

import asyncio
import ssl
import socket
import logging
from datetime import datetime, timezone
from dataclasses import dataclass, field

import aiohttp

logger = logging.getLogger(__name__)


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

    def __init__(self, http_timeout: float = 8.0, whois_timeout: float = 5.0):
        self.http_timeout = http_timeout
        self.whois_timeout = whois_timeout

    async def inspect_all(
        self, url: str, domain: str, registered_domain: str
    ) -> NetworkResult:
        """Run DNS, SSL, HTTP, and WHOIS inspections in parallel."""
        tasks = [
            self._check_dns(domain),
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

    async def _check_dns(self, domain: str) -> DNSResult:
        """DNS resolution + TTL + MX/NS analysis."""
        result = DNSResult()
        loop = asyncio.get_event_loop()

        try:
            import dns.resolver

            # A record
            try:
                answers = await loop.run_in_executor(
                    None, lambda: dns.resolver.resolve(domain, "A")
                )
                result.resolved = True
                result.ttl = answers.rrset.ttl
                if result.ttl is not None and result.ttl < 300:
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

            # MX records
            try:
                await loop.run_in_executor(
                    None, lambda: dns.resolver.resolve(domain, "MX")
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
        loop = asyncio.get_event_loop()

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
                result.is_new_cert = result.cert_age_days < 30

        except ssl.SSLCertVerificationError:
            result.error = "ssl_verification_failed"
        except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError):
            result.error = "ssl_connection_failed"
        except Exception as e:
            result.error = str(e)[:120]

        return result

    # ── HTTP ───────────────────────────────────────────────────

    async def _check_http(self, url: str, registered_domain: str) -> HTTPResult:
        """Follow redirects, inspect content, check scheme."""
        result = HTTPResult()
        try:
            timeout = aiohttp.ClientTimeout(total=self.http_timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, allow_redirects=True, ssl=False) as resp:
                    result.status_code = resp.status
                    result.final_url = str(resp.url)
                    result.redirect_count = len(resp.history)
                    result.server = resp.headers.get("Server")

                    # Scheme warning
                    if result.final_url.startswith("http://"):
                        result.scheme_warning = True

                    # Cross-domain redirect
                    if result.redirect_count > 0 and registered_domain:
                        from app.services.domain_reputation import get_registered_domain
                        final_reg = get_registered_domain(result.final_url)
                        if final_reg != registered_domain:
                            result.redirect_domain_mismatch = True

                    # Content inspection (HTML only, first 15KB)
                    ctype = resp.headers.get("Content-Type", "").lower()
                    if resp.status == 200 and "text/html" in ctype:
                        try:
                            text = (await resp.text())[:15000].lower()

                            if 'type="password"' in text or 'name="password"' in text:
                                result.content_flags.append("password_field")
                            if any(w in text for w in ("credit card", "billing address", "cvv")):
                                result.content_flags.append("billing_info_request")
                            if any(w in text for w in ("ssn", "social security")):
                                result.content_flags.append("sensitive_id_request")
                            if "geolocation.getcurrentposition" in text:
                                result.content_flags.append("geolocation_tracking")
                            if text.count("<iframe") > 3:
                                result.content_flags.append("excessive_iframes")
                            if "eval(atob(" in text or "eval(unescape(" in text:
                                result.content_flags.append("obfuscated_javascript")
                        except Exception:
                            pass

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
            loop = asyncio.get_event_loop()
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
        except Exception as e:
            result.error = str(e)[:120]

        return result


# Singleton
network_inspector = NetworkInspector()
