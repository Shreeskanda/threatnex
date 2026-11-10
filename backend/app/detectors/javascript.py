import re
from typing import List
from app.schemas.scan import Finding, SeverityLevel


class JavaScriptInspector:

    # Patterns for detection
    EVAL_PATTERN = re.compile(r'\beval\s*\(', re.IGNORECASE)
    DOC_WRITE_PATTERN = re.compile(r'document\.write\s*\(', re.IGNORECASE)
    ATOB_PATTERN = re.compile(r'\batob\s*\(', re.IGNORECASE)
    BTOA_PATTERN = re.compile(r'\bbtoa\s*\(', re.IGNORECASE)
    HEX_ENCODE_PATTERN = re.compile(r'\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}')
    CHARCODE_PATTERN = re.compile(r'String\.fromCharCode\s*\([\s\d,]+\)', re.IGNORECASE)
    LOCATION_MANIP_PATTERN = re.compile(
        r'(?:window|document)\.location\s*(?:=|\.replace|\.href\s*=|\.assign)',
        re.IGNORECASE
    )
    FORM_SUBMIT_EXTERNAL = re.compile(
        r'(?:fetch|XMLHttpRequest|\.ajax|axios)\s*\(\s*["\']https?://(?!(?:localhost|127\.0\.0\.1))',
        re.IGNORECASE
    )
    KEYLOGGER_PATTERN = re.compile(
        r'addEventListener\s*\(\s*["\'](?:keydown|keyup|keypress)["\']',
        re.IGNORECASE
    )
    CLIPBOARD_PATTERN = re.compile(
        r'(?:document\.execCommand\s*\(\s*["\']copy["\']|navigator\.clipboard)',
        re.IGNORECASE
    )
    COOKIE_STEAL_PATTERN = re.compile(
        r'document\.cookie.*(?:fetch|XMLHttpRequest|href\s*=)',
        re.IGNORECASE | re.DOTALL
    )
    SCRIPT_INJECT_PATTERN = re.compile(
        r'createElement\s*\(\s*["\']script["\']',
        re.IGNORECASE
    )
    DOWNLOAD_TRIGGER_PATTERN = re.compile(
        r'(?:\.download\s*=|createObjectURL|msSaveBlob)',
        re.IGNORECASE
    )
    OBFUSCATION_PATTERNS = [
        re.compile(r'\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){10,}'),  # Unicode escape abuse
        re.compile(r'(?:0x[0-9a-fA-F]+,?\s*){20,}'),  # Hex array
        re.compile(r'parseInt\([^)]+,\s*(?:16|8|2)\)', re.IGNORECASE),  # Radix parsing
    ]

    def inspect(self, js_content: str, source_url: str = "") -> List[Finding]:
        findings: List[Finding] = []
        if not js_content or not js_content.strip():
            return findings

        # 1. eval() usage
        eval_matches = self.EVAL_PATTERN.findall(js_content)
        if eval_matches:
            # Check for dynamic content in eval
            context_pattern = re.compile(r'eval\s*\(([^)]{10,})\)', re.IGNORECASE)
            dynamic_evals = context_pattern.findall(js_content)
            if dynamic_evals:
                findings.append(Finding(
                    title="Dynamic eval() Usage Detected",
                    description="The script uses eval() with dynamic content. This is a common obfuscation technique used to hide malicious code.",
                    severity=SeverityLevel.high,
                    evidence=f"eval() call with dynamic argument: {dynamic_evals[0][:80]}",
                    category="Code Obfuscation",
                ))

        # 2. document.write() with external content
        doc_writes = self.DOC_WRITE_PATTERN.findall(js_content)
        if doc_writes:
            # Check if external URL is being written
            write_context = re.compile(r'document\.write\s*\(([^;]{0,200})\)', re.IGNORECASE)
            contexts = write_context.findall(js_content)
            external_writes = [c for c in contexts if "http" in c.lower()]
            if external_writes:
                findings.append(Finding(
                    title="document.write() with External Content",
                    description="The script uses document.write() to inject external content, which can be used for drive-by downloads or phishing overlays.",
                    severity=SeverityLevel.high,
                    evidence=f"Content: {external_writes[0][:100]}",
                    category="Content Injection",
                ))

        # 3. Base64 decode patterns
        if self.ATOB_PATTERN.search(js_content):
            # Look for atob used with large strings or variables
            atob_context = re.compile(r'atob\s*\(([^)]+)\)', re.IGNORECASE)
            atob_calls = atob_context.findall(js_content)
            large_b64 = [c for c in atob_calls if len(c) > 20 or "+" in c]
            if large_b64:
                findings.append(Finding(
                    title="Base64 Decoding (atob) Detected",
                    description="The script decodes Base64 strings at runtime. This is commonly used to hide malicious payloads from static analysis.",
                    severity=SeverityLevel.high,
                    evidence=f"atob() call: {large_b64[0][:80]}",
                    category="Code Obfuscation",
                ))

        # 4. Hex / Unicode obfuscation
        hex_matches = self.HEX_ENCODE_PATTERN.findall(js_content)
        if hex_matches:
            findings.append(Finding(
                title="Hex String Obfuscation Detected",
                description="The script contains heavily hex-encoded strings, a common technique to evade signature-based detection.",
                severity=SeverityLevel.high,
                evidence=f"Hex pattern length: {len(hex_matches[0])} chars",
                category="Code Obfuscation",
            ))

        # 5. String.fromCharCode abuse
        charcode_matches = self.CHARCODE_PATTERN.findall(js_content)
        if len(charcode_matches) > 3:
            findings.append(Finding(
                title="Excessive String.fromCharCode Usage",
                description=f"Found {len(charcode_matches)} String.fromCharCode() calls. This is a classic obfuscation technique to hide malicious strings.",
                severity=SeverityLevel.high,
                evidence=f"{len(charcode_matches)} instances found",
                category="Code Obfuscation",
            ))
        elif charcode_matches:
            findings.append(Finding(
                title="String.fromCharCode Usage Detected",
                description="The script uses String.fromCharCode() which may be used to construct malicious strings.",
                severity=SeverityLevel.medium,
                evidence=charcode_matches[0][:80],
                category="Code Obfuscation",
            ))

        # 6. window.location manipulation
        location_matches = self.LOCATION_MANIP_PATTERN.findall(js_content)
        if location_matches:
            # Find the full context
            loc_context = re.compile(
                r'(?:window|document)\.location\s*(?:=|\.replace|\.href\s*=|\.assign)\s*([^\n;]{0,100})',
                re.IGNORECASE
            )
            contexts = loc_context.findall(js_content)
            external_redirects = [c.strip() for c in contexts if "http" in c.lower()]
            if external_redirects:
                findings.append(Finding(
                    title="Suspicious Location Redirect in JavaScript",
                    description="The script manipulates the browser location to redirect to an external URL.",
                    severity=SeverityLevel.high,
                    evidence=f"Redirect target: {external_redirects[0][:100]}",
                    category="Malicious Redirect",
                ))

        # 7. Credential harvesting — form submit to external
        fetch_matches = self.FORM_SUBMIT_EXTERNAL.findall(js_content)
        if fetch_matches:
            findings.append(Finding(
                title="Data Submission to External Server",
                description="The script sends data (possibly credentials) to an external server via fetch or XMLHttpRequest.",
                severity=SeverityLevel.critical,
                evidence=f"External submission detected",
                category="Credential Harvesting",
            ))

        # 8. Keylogging patterns
        if self.KEYLOGGER_PATTERN.search(js_content):
            # Check if combined with data exfiltration
            has_exfil = bool(
                re.search(r'(?:fetch|XMLHttpRequest|sendBeacon)', js_content, re.IGNORECASE)
            )
            severity = SeverityLevel.critical if has_exfil else SeverityLevel.high
            findings.append(Finding(
                title="Potential Keylogger Pattern Detected",
                description="The script listens to keyboard events" + (
                    " and appears to exfiltrate data, indicating a keylogger." if has_exfil
                    else ". Combined with other indicators, this may be a keylogger."
                ),
                severity=severity,
                evidence="Keyboard event listener + data transmission detected" if has_exfil else "Keyboard event listener detected",
                category="Keylogging",
            ))

        # 9. Clipboard access
        if self.CLIPBOARD_PATTERN.search(js_content):
            findings.append(Finding(
                title="Clipboard Access Detected",
                description="The script accesses the user's clipboard. Malicious scripts may read clipboard content to steal copied passwords or crypto addresses.",
                severity=SeverityLevel.medium,
                evidence="document.execCommand('copy') or navigator.clipboard API usage",
                category="Data Theft",
            ))

        # 10. Dynamic script injection
        if self.SCRIPT_INJECT_PATTERN.search(js_content):
            # Check if loading external URL
            inject_context = re.compile(
                r"createElement\s*\(\s*['\"]script['\"]\s*\)[\s\S]{0,200}",
                re.IGNORECASE
            )
            match = inject_context.search(js_content)
            if match and ("http" in match.group(0).lower() or "src" in match.group(0).lower()):
                findings.append(Finding(
                    title="Dynamic External Script Injection",
                    description="The script dynamically creates a <script> element loading external JavaScript, a common malware distribution technique.",
                    severity=SeverityLevel.high,
                    evidence=match.group(0)[:100],
                    category="Script Injection",
                ))

        # 11. Obfuscation indicators (general)
        obfuscation_count = 0
        for pattern in self.OBFUSCATION_PATTERNS:
            if pattern.search(js_content):
                obfuscation_count += 1
        if obfuscation_count >= 2:
            findings.append(Finding(
                title="Multiple Code Obfuscation Techniques Detected",
                description=f"The script uses {obfuscation_count} obfuscation techniques simultaneously. This strongly suggests malicious intent.",
                severity=SeverityLevel.critical,
                evidence=f"{obfuscation_count} obfuscation patterns matched",
                category="Code Obfuscation",
            ))

        # 12. Download triggers
        if self.DOWNLOAD_TRIGGER_PATTERN.search(js_content):
            findings.append(Finding(
                title="Unexpected Download Trigger",
                description="The script uses APIs that can trigger file downloads. This may be used for drive-by download attacks.",
                severity=SeverityLevel.medium,
                evidence="createObjectURL, .download attribute, or msSaveBlob detected",
                category="Drive-by Download",
            ))

        return findings
