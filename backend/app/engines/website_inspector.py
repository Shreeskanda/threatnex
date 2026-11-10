import asyncio
import logging
import time
from typing import List, Tuple, Dict, Any, Optional
from urllib.parse import urlparse, urljoin
import httpx

from app.schemas.scan import Finding, SeverityLevel
from app.detectors.phishing import PhishingDetector
from app.detectors.html_inspector import HTMLInspector
from app.detectors.javascript import JavaScriptInspector
from app.detectors.domain_intel import DomainIntelligence
from app.engines.url_inspector import URLInspector, _is_ssrf_target

logger = logging.getLogger(__name__)

# Try importing playwright
try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


class WebsiteInspector:
    def __init__(self):
        self.url_inspector = URLInspector()
        self.html_inspector = HTMLInspector()
        self.js_inspector = JavaScriptInspector()
        self.domain_intel = DomainIntelligence()
        self.phishing_detector = PhishingDetector()

    async def inspect(self, url: str) -> Tuple[List[Finding], Dict[str, Any]]:
        """
        Comprehensive website inspection combining:
        1. SSRF and Domain Intelligence
        2. HTTP Security Configuration & Headers
        3. Browser-based or HTTP-based DOM extraction
        4. Static JavaScript analysis
        5. Visual & Brand impersonation heuristic analysis
        """
        findings: List[Finding] = []
        metadata: Dict[str, Any] = {
            "inspected_url": url,
            "playwright_used": False,
            "network_requests": [],
            "third_party_domains": [],
            "scripts_analyzed": 0,
            "forms_found": 0,
            "screenshot": None,
        }

        # 1. Basic URL & SSRF check
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if not host:
            findings.append(Finding(
                title="Invalid Hostname",
                description="Unable to parse a valid hostname from the supplied URL.",
                severity=SeverityLevel.high,
                evidence=url,
                category="URL Validation"
            ))
            return findings, metadata

        if _is_ssrf_target(host):
            findings.append(Finding(
                title="SSRF Protection - Private Network Blocked",
                description=f"Destination address ({host}) resolves to an internal or reserved network range. Inspection blocked.",
                severity=SeverityLevel.critical,
                evidence=f"Target: {host}",
                category="SSRF Prevention"
            ))
            return findings, metadata

        # 2. Domain Intelligence
        domain_findings, domain_data = self.domain_intel.analyze(host, url)
        findings.extend(domain_findings)
        metadata["domain_info"] = domain_data

        # 3. Phishing Detector checks on URL
        url_findings = self.phishing_detector.check_url(url)
        findings.extend(url_findings)

        # 4. HTTP Headers and SSL inspection
        http_findings, http_meta = await self.url_inspector.inspect(url)
        findings.extend(http_findings)
        metadata["security_headers"] = http_meta.get("headers", {})
        metadata["http_status"] = http_meta.get("status_code")
        metadata["final_url"] = http_meta.get("final_url", url)

        # 5. Page Content & Script Inspection
        html_content = ""
        network_urls = []

        # Attempt Playwright for full dynamic DOM & network monitoring if available
        playwright_success = False
        if PLAYWRIGHT_AVAILABLE:
            try:
                playwright_findings, pw_meta = await self._inspect_with_playwright(url)
                findings.extend(playwright_findings)
                metadata.update(pw_meta)
                html_content = pw_meta.get("html", "")
                playwright_success = True
            except Exception as e:
                logger.warning(f"Playwright inspection fallback due to: {e}")

        # If Playwright not available or failed, fallback to HTTP GET fetch
        if not playwright_success:
            try:
                async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                    resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThreatNexBot/1.0"})
                    html_content = resp.text
                    metadata["final_url"] = str(resp.url)
            except Exception as e:
                findings.append(Finding(
                    title="Website Connection Failed",
                    description=f"Failed to fetch website content: {str(e)}",
                    severity=SeverityLevel.low,
                    evidence=str(e),
                    category="Network"
                ))

        if html_content:
            # Inspect HTML DOM
            html_findings = self.html_inspector.inspect(html_content, metadata.get("final_url", url))
            findings.extend(html_findings)

            # Extract and inspect inline and external JavaScript
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(html_content, "html.parser")
                scripts = soup.find_all("script")
                metadata["scripts_analyzed"] = len(scripts)
                metadata["forms_found"] = len(soup.find_all("form"))

                # Analyze inline scripts
                for idx, script in enumerate(scripts[:10]):  # Analyze top 10 scripts
                    js_code = script.string or script.text or ""
                    if js_code.strip():
                        js_findings = self.js_inspector.inspect(js_code, f"inline_script_{idx+1}")
                        findings.extend(js_findings)
            except Exception as e:
                logger.debug(f"BS4 script parsing error: {e}")

        # Visual/Brand Phishing heuristic check
        if html_content:
            lower_html = html_content.lower()
            banking_terms = ["bank", "netbanking", "login to your account", "debit card", "cvv", "atm pin", "internet banking", "kyc update"]
            gov_terms = ["income tax", "uidai", "aadhaar", "police department", "cyber cell", "arrest warrant"]
            
            found_bank = [t for t in banking_terms if t in lower_html]
            if len(found_bank) >= 3 and not any(legit in host for legit in ["sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com"]):
                findings.append(Finding(
                    title="Potential Fake Banking Portal",
                    description="The page contains multiple financial/banking keywords and credential requests while hosted on an unverified domain.",
                    severity=SeverityLevel.high,
                    evidence=f"Matched indicators: {', '.join(found_bank[:5])}",
                    category="Brand Impersonation"
                ))

            found_gov = [t for t in gov_terms if t in lower_html]
            if len(found_gov) >= 2 and not host.endswith(".gov.in") and not host.endswith(".nic.in"):
                findings.append(Finding(
                    title="Potential Government Impersonation",
                    description="The website displays government department names/notices but does not belong to an official .gov.in or .nic.in domain.",
                    severity=SeverityLevel.critical,
                    evidence=f"Host: {host}, Indicators: {', '.join(found_gov)}",
                    category="Government Impersonation"
                ))

        # Deduplicate findings
        unique_findings = []
        seen = set()
        for f in findings:
            key = (f.title, f.evidence)
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        return unique_findings, metadata

    async def _inspect_with_playwright(self, url: str) -> Tuple[List[Finding], Dict[str, Any]]:
        findings: List[Finding] = []
        meta: Dict[str, Any] = {
            "playwright_used": True,
            "network_requests": [],
            "third_party_domains": [],
        }
        network_reqs = []
        base_domain = urlparse(url).netloc.split(":")[0]

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThreatNexSecurityScanner/1.0",
                viewport={"width": 1280, "height": 800},
                ignore_https_errors=True
            )
            page = await context.new_page()

            # Monitor network requests
            def handle_request(req):
                req_url = req.url
                req_domain = urlparse(req_url).netloc.split(":")[0]
                if req_domain and req_domain != base_domain:
                    if req_domain not in meta["third_party_domains"]:
                        meta["third_party_domains"].append(req_domain)
                if len(network_reqs) < 50:
                    network_reqs.append(req_url)

            page.on("request", handle_request)

            try:
                response = await page.goto(url, wait_until="domcontentloaded", timeout=20000)
                meta["final_url"] = page.url
                meta["html"] = await page.content()
                meta["network_requests"] = network_reqs

                # Check for suspicious mixed content
                if url.startswith("https://"):
                    http_resources = [r for r in network_reqs if r.startswith("http://")]
                    if http_resources:
                        findings.append(Finding(
                            title="Mixed Content Loaded",
                            description="The secure HTTPS page loaded insecure HTTP resources, exposing visitors to MITM attacks.",
                            severity=SeverityLevel.medium,
                            evidence=f"Insecure resources: {len(http_resources)}",
                            category="Transport Security"
                        ))

            finally:
                await browser.close()

        return findings, meta
