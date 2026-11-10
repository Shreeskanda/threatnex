import re
from typing import List, Optional
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from app.schemas.scan import Finding, SeverityLevel


SUSPICIOUS_INPUT_NAMES = {
    "password", "passwd", "pwd", "pass", "otp", "pin", "cvv", "cvc",
    "card", "cardnumber", "cc", "ccnum", "credit", "debit", "expiry",
    "exp", "expdate", "ssn", "pan", "aadhaar", "aadhar", "account",
    "routing", "ifsc", "swift", "iban",
}

PAYMENT_FIELD_PATTERNS = re.compile(
    r"(?i)(credit[_\-\s]?card|debit[_\-\s]?card|card[_\-\s]?number|"
    r"cvv|cvc|cvc2|card[_\-\s]?pin|expir[a-z]+|billing)"
)


class HTMLInspector:

    def inspect(self, html_content: str, base_url: str = "") -> List[Finding]:
        findings: List[Finding] = []
        if not html_content:
            return findings

        try:
            soup = BeautifulSoup(html_content, "html.parser")
        except Exception:
            return findings

        base_domain = ""
        if base_url:
            try:
                parsed = urlparse(base_url)
                base_domain = parsed.netloc.lower()
            except Exception:
                pass

        # 1. Forms analysis
        findings.extend(self._inspect_forms(soup, base_url, base_domain))

        # 2. Password input fields
        findings.extend(self._inspect_input_fields(soup))

        # 3. Hidden fields with suspicious names
        findings.extend(self._inspect_hidden_fields(soup))

        # 4. Invisible elements with suspicious content
        findings.extend(self._inspect_invisible_elements(soup))

        # 5. Iframes
        findings.extend(self._inspect_iframes(soup, base_domain))

        # 6. Meta redirects
        findings.extend(self._inspect_meta_redirects(soup))

        # 7. Base tag manipulation
        findings.extend(self._inspect_base_tag(soup, base_domain))

        # 8. Suspicious onclick handlers
        findings.extend(self._inspect_event_handlers(soup))

        return findings

    def _is_external(self, url: str, base_domain: str) -> bool:
        """Check if a URL is external relative to base_domain."""
        if not url or not base_domain:
            return False
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                return False
            return parsed.netloc.lower() != base_domain
        except Exception:
            return False

    def _inspect_forms(self, soup: BeautifulSoup, base_url: str, base_domain: str) -> List[Finding]:
        findings = []
        forms = soup.find_all("form")
        for form in forms:
            action = form.get("action", "")
            method = form.get("method", "get").lower()

            # Form posting to external domain
            if action and self._is_external(action, base_domain):
                findings.append(Finding(
                    title="Form Submits Data to External Domain",
                    description="A form on this page submits user input to an external domain, which may indicate credential harvesting.",
                    severity=SeverityLevel.critical,
                    evidence=f"Form action: {action}",
                    category="Credential Harvesting",
                ))

            # Form with password fields
            has_password = bool(form.find("input", {"type": "password"}))
            has_text = bool(form.find("input", {"type": ["text", "email", "tel"]}))
            if has_password and has_text:
                severity = SeverityLevel.medium
                desc = "Login form detected."
                if action and action.startswith("http") and self._is_external(action, base_domain):
                    severity = SeverityLevel.critical
                    desc = "Login form that submits credentials to an external server."
                elif not action or action in ["", "#", "javascript:void(0)"]:
                    severity = SeverityLevel.high
                    desc = "Login form with no clear action URL — credentials may be harvested via JavaScript."
                findings.append(Finding(
                    title="Login Form Detected",
                    description=desc,
                    severity=severity,
                    evidence=f"Form action: '{action}', Method: {method}",
                    category="Credential Harvesting",
                ))

            # Payment card form
            form_text = str(form).lower()
            if PAYMENT_FIELD_PATTERNS.search(form_text):
                findings.append(Finding(
                    title="Payment Card Input Form Detected",
                    description="This form appears to collect payment card information (card number, CVV, expiry). Verify this is a legitimate payment page.",
                    severity=SeverityLevel.high,
                    evidence="Payment-related input fields found in form",
                    category="Financial Data Collection",
                ))

        return findings

    def _inspect_input_fields(self, soup: BeautifulSoup) -> List[Finding]:
        findings = []
        # Standalone password fields outside forms
        password_inputs = soup.find_all("input", {"type": "password"})
        for inp in password_inputs:
            if not inp.find_parent("form"):
                findings.append(Finding(
                    title="Orphan Password Input Field",
                    description="A password input field exists outside of a form element. This could be used to capture credentials via JavaScript.",
                    severity=SeverityLevel.high,
                    evidence=f"Input name: {inp.get('name', 'unnamed')}",
                    category="Credential Harvesting",
                ))
        return findings

    def _inspect_hidden_fields(self, soup: BeautifulSoup) -> List[Finding]:
        findings = []
        hidden_inputs = soup.find_all("input", {"type": "hidden"})
        suspicious = []
        for inp in hidden_inputs:
            name = (inp.get("name") or "").lower()
            value = (inp.get("value") or "").lower()
            if any(s in name for s in SUSPICIOUS_INPUT_NAMES):
                suspicious.append(f"name='{inp.get('name')}' value='{inp.get('value', '')[:30]}'")
        if suspicious:
            findings.append(Finding(
                title="Suspicious Hidden Input Fields",
                description="Hidden form fields with security-sensitive names detected. These may be used to silently capture or transmit sensitive data.",
                severity=SeverityLevel.medium,
                evidence=f"Fields: {'; '.join(suspicious[:3])}",
                category="Data Exfiltration",
            ))
        return findings

    def _inspect_invisible_elements(self, soup: BeautifulSoup) -> List[Finding]:
        findings = []
        # Elements with suspicious inline styles hiding them
        invisible_patterns = [
            re.compile(r"display\s*:\s*none", re.IGNORECASE),
            re.compile(r"visibility\s*:\s*hidden", re.IGNORECASE),
            re.compile(r"opacity\s*:\s*0(?:\.0+)?\b", re.IGNORECASE),
            re.compile(r"font-size\s*:\s*0", re.IGNORECASE),
            re.compile(r"height\s*:\s*0(?:px)?", re.IGNORECASE),
            re.compile(r"width\s*:\s*0(?:px)?", re.IGNORECASE),
        ]
        interesting_tags = soup.find_all(["div", "span", "p", "form", "input", "a"])
        for tag in interesting_tags:
            style = tag.get("style", "")
            is_invisible = any(pat.search(style) for pat in invisible_patterns)
            if is_invisible:
                text_content = tag.get_text(strip=True)
                if len(text_content) > 20:  # Only flag if there's substantial hidden content
                    findings.append(Finding(
                        title="Hidden Element with Suspicious Content",
                        description="An invisible page element contains substantial text. This may be used for cloaking or hidden forms.",
                        severity=SeverityLevel.medium,
                        evidence=f"Tag: <{tag.name}>, Content preview: {text_content[:80]}",
                        category="Cloaking",
                    ))
                    break  # Report only first instance
        return findings

    def _inspect_iframes(self, soup: BeautifulSoup, base_domain: str) -> List[Finding]:
        findings = []
        iframes = soup.find_all("iframe")
        for iframe in iframes:
            src = iframe.get("src", "")
            sandbox = iframe.get("sandbox")
            if src and self._is_external(src, base_domain):
                severity = SeverityLevel.medium if sandbox is not None else SeverityLevel.high
                findings.append(Finding(
                    title="Cross-Origin iFrame Detected",
                    description=f"An iFrame loads content from an external domain. Without sandboxing, this can be used for phishing overlays or clickjacking.",
                    severity=severity,
                    evidence=f"iFrame src: {src[:100]}",
                    category="Iframe Injection",
                ))
            elif not src:
                findings.append(Finding(
                    title="Blank iFrame Detected",
                    description="An iFrame with no source is present. It may be populated dynamically by JavaScript for malicious purposes.",
                    severity=SeverityLevel.low,
                    evidence="<iframe> with no src attribute",
                    category="Iframe Injection",
                ))
        return findings

    def _inspect_meta_redirects(self, soup: BeautifulSoup) -> List[Finding]:
        findings = []
        meta_tags = soup.find_all("meta", {"http-equiv": re.compile(r"refresh", re.IGNORECASE)})
        for meta in meta_tags:
            content = meta.get("content", "")
            url_match = re.search(r"url\s*=\s*(.+)", content, re.IGNORECASE)
            if url_match:
                redirect_url = url_match.group(1).strip().strip("'\"")
                findings.append(Finding(
                    title="Meta Refresh Redirect Detected",
                    description="The page uses a meta refresh tag to redirect users. This technique is used to redirect victims after showing fake login pages.",
                    severity=SeverityLevel.medium,
                    evidence=f"Redirect to: {redirect_url[:100]}",
                    category="Suspicious Redirect",
                ))
        return findings

    def _inspect_base_tag(self, soup: BeautifulSoup, base_domain: str) -> List[Finding]:
        findings = []
        base_tags = soup.find_all("base")
        for base in base_tags:
            href = base.get("href", "")
            if href and self._is_external(href, base_domain):
                findings.append(Finding(
                    title="Base Tag Pointing to External Domain",
                    description="The HTML <base> tag is set to an external domain, which hijacks all relative URLs on the page.",
                    severity=SeverityLevel.high,
                    evidence=f"Base href: {href}",
                    category="URL Hijacking",
                ))
        return findings

    def _inspect_event_handlers(self, soup: BeautifulSoup) -> List[Finding]:
        findings = []
        suspicious_handlers = []
        for tag in soup.find_all(True):
            onclick = tag.get("onclick", "")
            onsubmit = tag.get("onsubmit", "")
            for handler_code in [onclick, onsubmit]:
                if any(keyword in handler_code.lower() for keyword in [
                    "document.location", "window.location", "fetch(", "xmlhttp",
                    "eval(", "atob(", "fromcharcode",
                ]):
                    suspicious_handlers.append(
                        f"<{tag.name}> {handler_code[:60]}"
                    )
        if suspicious_handlers:
            findings.append(Finding(
                title="Suspicious Inline Event Handlers",
                description="Inline JavaScript event handlers perform suspicious operations like redirects, fetch calls, or obfuscated code execution.",
                severity=SeverityLevel.medium,
                evidence=f"Examples: {'; '.join(suspicious_handlers[:2])}",
                category="Malicious JavaScript",
            ))
        return findings
