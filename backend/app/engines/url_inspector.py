import ipaddress
import logging
import time
from typing import List, Tuple, Dict
from urllib.parse import urlparse

import httpx

from app.schemas.scan import Finding, SeverityLevel

logger = logging.getLogger(__name__)

PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "HSTS (Strict-Transport-Security)",
        "severity": SeverityLevel.medium,
        "description": "HSTS prevents downgrade attacks and cookie hijacking by enforcing HTTPS connections.",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "severity": SeverityLevel.medium,
        "description": "X-Frame-Options prevents clickjacking attacks by controlling whether the page can be embedded in frames.",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "severity": SeverityLevel.low,
        "description": "X-Content-Type-Options prevents MIME type sniffing which can lead to XSS attacks.",
    },
    "content-security-policy": {
        "name": "Content-Security-Policy (CSP)",
        "severity": SeverityLevel.medium,
        "description": "CSP header controls resources the browser is allowed to load, mitigating XSS and data injection attacks.",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "severity": SeverityLevel.low,
        "description": "Referrer-Policy controls how much referrer information is shared with other sites.",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "severity": SeverityLevel.low,
        "description": "Permissions-Policy controls access to browser features like camera, microphone, and geolocation.",
    },
}


def _is_ssrf_target(host: str) -> bool:
    """Check if host could be an SSRF target (private/internal IP or localhost)."""
    if host in ("localhost", "0.0.0.0"):
        return True
    if host.endswith(".local") or host.endswith(".internal") or host.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return any(ip in network for network in PRIVATE_NETWORKS)
    except ValueError:
        pass
    return False


class URLInspector:

    async def inspect(self, url: str) -> Tuple[List[Finding], Dict]:
        findings: List[Finding] = []
        metadata: Dict = {}
        start_time = time.time()

        try:
            parsed = urlparse(url)
        except Exception:
            findings.append(Finding(
                title="Invalid URL",
                description="The provided URL could not be parsed. It may be malformed.",
                severity=SeverityLevel.high,
                evidence=url,
                category="Invalid Input",
            ))
            return findings, metadata

        host = parsed.hostname or ""
        scheme = parsed.scheme.lower()

        # 1. SSRF prevention
        if _is_ssrf_target(host):
            findings.append(Finding(
                title="SSRF Target Blocked",
                description=f"The URL targets a private or internal address ({host}). Inspection blocked to prevent SSRF.",
                severity=SeverityLevel.critical,
                evidence=f"Host: {host}",
                category="SSRF Prevention",
            ))
            metadata["ssrf_blocked"] = True
            return findings, metadata

        if scheme not in ("http", "https"):
            findings.append(Finding(
                title="Non-HTTP(S) Scheme",
                description=f"The URL uses the '{scheme}' scheme. Only HTTP and HTTPS URLs are inspected.",
                severity=SeverityLevel.medium,
                evidence=f"Scheme: {scheme}",
                category="Suspicious URL Structure",
            ))
            return findings, metadata

        # 2. HTTP check
        if scheme == "http":
            findings.append(Finding(
                title="Insecure HTTP Connection",
                description="The site uses plain HTTP instead of HTTPS. Data transmitted may be intercepted.",
                severity=SeverityLevel.medium,
                evidence=f"Scheme: {scheme}",
                category="Transport Security",
            ))

        # 3. Make HTTP request
        headers_found = {}
        redirect_chain = []
        final_url = url
        status_code = None
        response_time_ms = 0
        ssl_error = False
        cookie_findings = []
        set_cookie_header = None

        try:
            async with httpx.AsyncClient(
                timeout=10.0,
                follow_redirects=True,
                max_redirects=5,
                verify=True,
            ) as client:
                req_start = time.time()
                response = await client.get(url, headers={"User-Agent": "Mozilla/5.0 ThreatNexBot/1.0"})
                response_time_ms = int((time.time() - req_start) * 1000)

                status_code = response.status_code
                headers_found = dict(response.headers)
                final_url = str(response.url)
                set_cookie_header = response.headers.get("set-cookie", "")

                # Collect redirect history
                for hist in response.history:
                    redirect_chain.append({
                        "url": str(hist.url),
                        "status": hist.status_code,
                    })

        except httpx.SSLError as e:
            ssl_error = True
            findings.append(Finding(
                title="SSL/TLS Certificate Error",
                description=f"The site's SSL certificate is invalid or untrusted. This may indicate a man-in-the-middle attack or an improperly configured server.",
                severity=SeverityLevel.high,
                evidence=str(e)[:150],
                category="Transport Security",
            ))
            # Retry without verification to continue analysis
            try:
                async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, max_redirects=5, verify=False) as client:
                    response = await client.get(url, headers={"User-Agent": "Mozilla/5.0 ThreatNexBot/1.0"})
                    status_code = response.status_code
                    headers_found = dict(response.headers)
                    final_url = str(response.url)
                    set_cookie_header = response.headers.get("set-cookie", "")
            except Exception:
                pass

        except httpx.TooManyRedirects:
            findings.append(Finding(
                title="Excessive Redirects",
                description="The URL triggered more than 5 redirects. This could indicate redirect abuse or a phishing chain.",
                severity=SeverityLevel.medium,
                evidence="Redirect limit (5) exceeded",
                category="Suspicious Redirect",
            ))
        except httpx.ConnectTimeout:
            findings.append(Finding(
                title="Connection Timeout",
                description="The server did not respond within 10 seconds. The site may be down or deliberately slow.",
                severity=SeverityLevel.low,
                evidence="Connection timeout after 10s",
                category="Availability",
            ))
            return findings, {"status": "timeout", "url": url}
        except Exception as e:
            findings.append(Finding(
                title="Connection Failed",
                description=f"Unable to connect to the URL: {str(e)[:100]}",
                severity=SeverityLevel.low,
                evidence=str(e)[:150],
                category="Availability",
            ))
            return findings, {"status": "error", "url": url, "error": str(e)[:100]}

        # 4. Redirect chain analysis
        if redirect_chain:
            metadata["redirect_chain"] = redirect_chain
            metadata["redirect_count"] = len(redirect_chain)
            if len(redirect_chain) >= 3:
                findings.append(Finding(
                    title=f"Long Redirect Chain ({len(redirect_chain)} hops)",
                    description="The URL goes through multiple redirects. Phishing links often use redirect chains to obscure the final destination.",
                    severity=SeverityLevel.medium,
                    evidence=f"Chain: {' → '.join([r['url'][:50] for r in redirect_chain[:3]])} → {final_url[:50]}",
                    category="Suspicious Redirect",
                ))

            # Check if final domain differs significantly from initial
            try:
                initial_host = urlparse(url).netloc
                final_host = urlparse(final_url).netloc
                if initial_host != final_host:
                    findings.append(Finding(
                        title="Redirect to Different Domain",
                        description=f"The URL redirects from '{initial_host}' to '{final_host}'. Verify this destination is expected.",
                        severity=SeverityLevel.medium,
                        evidence=f"Original: {initial_host} → Final: {final_host}",
                        category="Suspicious Redirect",
                    ))
            except Exception:
                pass

        # 5. Security headers check
        missing_headers = []
        for header_name, header_info in SECURITY_HEADERS.items():
            if header_name not in headers_found:
                missing_headers.append(header_info["name"])

        if len(missing_headers) >= 4:
            findings.append(Finding(
                title="Multiple Critical Security Headers Missing",
                description=f"The site is missing {len(missing_headers)} important security headers, leaving users vulnerable to various attacks.",
                severity=SeverityLevel.high,
                evidence=f"Missing: {', '.join(missing_headers)}",
                category="Security Headers",
            ))
        elif missing_headers:
            findings.append(Finding(
                title="Security Headers Missing",
                description=f"The site is missing security headers: {', '.join(missing_headers)}.",
                severity=SeverityLevel.low,
                evidence=f"Missing: {', '.join(missing_headers)}",
                category="Security Headers",
            ))

        # 6. Cookie security flags
        if set_cookie_header:
            cookie_issues = []
            if "secure" not in set_cookie_header.lower():
                cookie_issues.append("Secure flag missing")
            if "httponly" not in set_cookie_header.lower():
                cookie_issues.append("HttpOnly flag missing")
            if "samesite" not in set_cookie_header.lower():
                cookie_issues.append("SameSite flag missing")
            if cookie_issues:
                findings.append(Finding(
                    title="Insecure Cookie Configuration",
                    description=f"Cookies are set without important security flags: {', '.join(cookie_issues)}. This can expose session cookies to theft.",
                    severity=SeverityLevel.medium,
                    evidence=f"Issues: {', '.join(cookie_issues)}",
                    category="Cookie Security",
                ))

        # 7. Status code analysis
        if status_code:
            if status_code == 403:
                findings.append(Finding(
                    title="Access Forbidden (403)",
                    description="The server returned a 403 Forbidden response. The URL may be restricted.",
                    severity=SeverityLevel.info,
                    evidence=f"HTTP {status_code}",
                    category="HTTP Response",
                ))
            elif status_code >= 500:
                findings.append(Finding(
                    title=f"Server Error Response ({status_code})",
                    description="The server returned an error response.",
                    severity=SeverityLevel.info,
                    evidence=f"HTTP {status_code}",
                    category="HTTP Response",
                ))

        # Build metadata
        metadata.update({
            "url": url,
            "final_url": final_url,
            "status_code": status_code,
            "response_time_ms": response_time_ms,
            "redirect_count": len(redirect_chain),
            "ssl_error": ssl_error,
            "headers": {
                k: v for k, v in headers_found.items()
                if k in SECURITY_HEADERS or k in ("server", "content-type", "x-powered-by")
            },
            "missing_security_headers": missing_headers,
            "scan_duration_ms": int((time.time() - start_time) * 1000),
        })

        return findings, metadata
