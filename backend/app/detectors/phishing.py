import re
import urllib.parse
from typing import List, Tuple
from app.schemas.scan import Finding, SeverityLevel


SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".work", ".click",
    ".link", ".top", ".pw", ".cc", ".su", ".biz", ".info", ".name",
    ".mobi", ".rocks", ".win", ".download", ".loan", ".review", ".stream",
    ".gdn", ".racing", ".date", ".trade", ".accountant", ".bid",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "buff.ly",
    "is.gd", "cli.gs", "pic.gd", "dlvr.it", "short.ie", "tiny.cc",
    "lnkd.in", "db.tt", "qr.ae", "adf.ly", "bitly.com", "tr.im",
    "rb.gy", "cutt.ly", "shorturl.at", "tiny.one", "rebrand.ly",
    "t.ly", "urlz.fr", "shortlink.gg",
}

PHISHING_KEYWORDS_PATH = [
    "login", "signin", "verify", "secure", "account", "update", "confirm",
    "banking", "password", "credential", "authenticate", "validation",
    "restore", "recover", "unlock", "support", "helpdesk", "service",
    "notification", "alert", "security", "protect", "access",
]

URGENCY_PATTERNS = [
    r"(?i)(urgent|immediately|right\s+now|act\s+now|expire[sd]?|deadline|limited\s+time|last\s+chance|final\s+notice)",
    r"(?i)(your\s+account\s+(will\s+be\s+)?(suspended|locked|closed|disabled|terminated))",
    r"(?i)(unusual\s+activity|suspicious\s+login|unauthorized\s+access)",
    r"(?i)(within\s+\d+\s+(hour|minute|day))",
]

OTP_PASSWORD_PATTERNS = [
    r"(?i)(share\s+(your\s+)?(otp|one[- ]time[- ]password|verification\s+code))",
    r"(?i)(enter\s+the\s+otp|provide\s+(the\s+)?otp)",
    r"(?i)(otp\s+(is|was|will\s+be)\s+\d{4,8})",
    r"(?i)(don'?t\s+share\s+(your\s+)?otp|never\s+share\s+(your\s+)?otp)",  # legit warning ironically
    r"(?i)(password.*reset|reset.*password)",
    r"(?i)(share\s+your\s+password|provide\s+your\s+password)",
]

FINANCIAL_THREAT_PATTERNS = [
    r"(?i)(fine\s+of\s+(rs\.?|inr|rupees?)\s*[\d,]+)",
    r"(?i)(penalty|arrest|court|FIR|legal\s+action|case\s+filed)",
    r"(?i)(warrant\s+(issued|pending)|summon(s|ed))",
    r"(?i)(cyber\s+crime\s+department|CBI|ED\s+(enforcement|department)|income\s+tax\s+department)",
    r"(?i)(immediate\s+payment|pay\s+immediately|transfer\s+(money|funds)\s+immediately)",
]

IMPERSONATION_KEYWORDS = [
    r"(?i)\b(RBI|Reserve\s+Bank|CBI|Central\s+Bureau|income\s+tax|IT\s+department)\b",
    r"(?i)\b(police|court|judge|magistrate|enforcement\s+directorate|ED)\b",
    r"(?i)\b(TRAI|SEBI|IRDA|UIDAI|Aadhaar\s+authority|ministry)\b",
    r"(?i)\b(narcotics|customs|immigration|interpol|CID)\b",
]

FAKE_PRIZE_PATTERNS = [
    r"(?i)(you\s+(have\s+)?(won|win|selected|chosen|awarded|lucky))",
    r"(?i)(congratulations?[!,.]?\s+(you|your))",
    r"(?i)(prize\s+(money|winner)|lottery\s+(winner|jackpot))",
    r"(?i)(claim\s+(your\s+)?(prize|reward|gift|money|cash))",
    r"(?i)(lucky\s+(draw|winner|customer|number))",
]

JOB_SCAM_PATTERNS = [
    r"(?i)(work\s+from\s+home.*earn|earn.*work\s+from\s+home)",
    r"(?i)(part[- ]time\s+job.*₹|Rs\.?\s*\d+.*per\s+(day|hour|week))",
    r"(?i)(no\s+experience\s+required.*salary|guaranteed\s+(income|salary|earnings))",
    r"(?i)(registration\s+fee.*job|job.*registration\s+fee|joining\s+fee)",
]

INVESTMENT_SCAM_PATTERNS = [
    r"(?i)(\d+%\s*(guaranteed|assured|fixed)\s+(return|profit|interest))",
    r"(?i)(double\s+your\s+(money|investment)|triple\s+your)",
    r"(?i)(risk[- ]free\s+investment|no\s+risk.*invest)",
    r"(?i)(crypto.*guaranteed|bitcoin.*profit|forex.*sure)",
]

BRAND_LOOKALIKES = {
    "google": ["g00gle", "gooogle", "g0ogle", "googIe", "goog1e"],
    "facebook": ["faceb00k", "facebok", "faceboook", "f4cebook"],
    "paypal": ["paypa1", "paypai", "paypall", "paypa-l"],
    "amazon": ["amaz0n", "amazoon", "arnazon", "amozon"],
    "microsoft": ["micros0ft", "microsofit", "microsft"],
    "apple": ["app1e", "appIe", "aple", "aplle"],
    "netflix": ["netf1ix", "netfl1x", "net-flix"],
    "sbi": ["sbl", "sb1", "s-bi", "sbibank"],
    "hdfc": ["hdf-c", "hdfcbank", "hdfc-bank"],
    "icici": ["icicl", "icic1"],
    "paytm": ["paytnn", "payt-m", "pa-ytm"],
    "irctc": ["irct-c", "irtcc"],
}


class PhishingDetector:

    def check_url(self, url: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            parsed = urllib.parse.urlparse(url)
        except Exception:
            return findings

        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
        full_path = (path + "?" + query).lower() if query else path

        # 1. IP address in URL
        ip_pattern = re.compile(
            r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?$"
        )
        if ip_pattern.match(domain):
            findings.append(Finding(
                title="IP Address Used Instead of Domain",
                description="The URL uses a raw IP address instead of a legitimate domain name. Phishing sites often use IPs to hide their identity.",
                severity=SeverityLevel.high,
                evidence=f"Host: {domain}",
                category="Suspicious URL Structure",
            ))

        # 2. Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                findings.append(Finding(
                    title=f"High-Risk TLD Detected: {tld}",
                    description=f"The domain uses the TLD '{tld}' which is frequently associated with free domain abuse and phishing campaigns.",
                    severity=SeverityLevel.medium,
                    evidence=f"Domain: {domain}",
                    category="Suspicious Domain",
                ))
                break

        # 3. Excessive subdomains (> 3 dots)
        subdomain_count = domain.count(".")
        if subdomain_count > 3:
            findings.append(Finding(
                title="Excessive Subdomains",
                description=f"The URL contains {subdomain_count} subdomain levels. Legitimate sites rarely use more than 3. This may be an attempt to obscure the actual domain.",
                severity=SeverityLevel.medium,
                evidence=f"Domain: {domain}",
                category="Suspicious URL Structure",
            ))

        # 4. Hyphen abuse (more than 2 hyphens in domain)
        hostname_part = domain.split(":")[0]
        labels = hostname_part.split(".")
        for label in labels:
            if label.count("-") >= 3:
                findings.append(Finding(
                    title="Hyphen Abuse in Domain",
                    description="The domain contains multiple hyphens which is a common technique used to create lookalike domains.",
                    severity=SeverityLevel.low,
                    evidence=f"Domain label: {label}",
                    category="Suspicious Domain",
                ))
                break

        # 5. URL length > 75 chars
        if len(url) > 75:
            severity = SeverityLevel.medium if len(url) > 100 else SeverityLevel.low
            findings.append(Finding(
                title="Excessively Long URL",
                description=f"The URL is {len(url)} characters long. Overly long URLs are often used to hide malicious domains or confuse users.",
                severity=severity,
                evidence=f"URL length: {len(url)} chars",
                category="Suspicious URL Structure",
            ))

        # 6. Phishing keywords in path/query
        matched_keywords = [kw for kw in PHISHING_KEYWORDS_PATH if kw in full_path]
        if len(matched_keywords) >= 2:
            findings.append(Finding(
                title="Multiple Phishing Keywords in URL Path",
                description=f"The URL path/query contains multiple keywords commonly found in phishing URLs.",
                severity=SeverityLevel.medium,
                evidence=f"Keywords found: {', '.join(matched_keywords[:5])}",
                category="Phishing Indicators",
            ))
        elif len(matched_keywords) == 1:
            findings.append(Finding(
                title="Phishing Keyword in URL Path",
                description=f"The URL path contains a keyword commonly found in phishing URLs.",
                severity=SeverityLevel.low,
                evidence=f"Keyword: {matched_keywords[0]}",
                category="Phishing Indicators",
            ))

        # 7. URL shortener detection
        clean_domain = domain.lstrip("www.")
        if clean_domain in URL_SHORTENERS:
            findings.append(Finding(
                title="URL Shortener Detected",
                description=f"This URL uses a URL shortening service ({clean_domain}). URL shorteners can disguise malicious destinations.",
                severity=SeverityLevel.medium,
                evidence=f"Shortener service: {clean_domain}",
                category="URL Obfuscation",
            ))

        # 8. Brand lookalike / typosquatting
        findings.extend(self.check_domain(domain))

        # 9. HTTP (not HTTPS)
        if parsed.scheme == "http":
            findings.append(Finding(
                title="Insecure HTTP Connection",
                description="The URL uses HTTP instead of HTTPS. Legitimate websites that handle sensitive data always use HTTPS.",
                severity=SeverityLevel.low,
                evidence=f"Scheme: {parsed.scheme}",
                category="Security Configuration",
            ))

        # 10. Suspicious @ symbol in URL (credential passing)
        if "@" in parsed.netloc:
            findings.append(Finding(
                title="Credential-Style URL Structure",
                description="The URL contains an '@' symbol in the domain part, which is a known phishing technique to hide the actual destination.",
                severity=SeverityLevel.high,
                evidence=f"URL: {url[:100]}",
                category="URL Obfuscation",
            ))

        return findings

    def check_text(self, text: str) -> List[Finding]:
        findings: List[Finding] = []
        if not text:
            return findings

        # 1. Urgency language
        urgency_matches = []
        for pattern in URGENCY_PATTERNS:
            m = re.search(pattern, text)
            if m:
                urgency_matches.append(m.group(0))
        if len(urgency_matches) >= 2:
            findings.append(Finding(
                title="Multiple Urgency Indicators",
                description="The text contains multiple phrases creating artificial urgency, a hallmark of phishing and scam messages.",
                severity=SeverityLevel.high,
                evidence=f"Phrases: {'; '.join(urgency_matches[:3])}",
                category="Social Engineering",
            ))
        elif urgency_matches:
            findings.append(Finding(
                title="Urgency Language Detected",
                description="The text uses urgency language to pressure the recipient into taking immediate action.",
                severity=SeverityLevel.medium,
                evidence=urgency_matches[0],
                category="Social Engineering",
            ))

        # 2. OTP/password requests
        otp_matches = []
        for pattern in OTP_PASSWORD_PATTERNS:
            m = re.search(pattern, text)
            if m:
                otp_matches.append(m.group(0))
        if otp_matches:
            findings.append(Finding(
                title="OTP or Password Request Detected",
                description="The text requests sharing of OTP or password. Legitimate organizations never ask for this information.",
                severity=SeverityLevel.critical,
                evidence=otp_matches[0],
                category="Credential Harvesting",
            ))

        # 3. Financial threats
        threat_matches = []
        for pattern in FINANCIAL_THREAT_PATTERNS:
            m = re.search(pattern, text)
            if m:
                threat_matches.append(m.group(0))
        if len(threat_matches) >= 2:
            findings.append(Finding(
                title="Multiple Financial Threat Indicators",
                description="The text contains multiple threats of legal/financial consequences, characteristic of 'Digital Arrest' and other authority scams.",
                severity=SeverityLevel.critical,
                evidence=f"Phrases: {'; '.join(threat_matches[:3])}",
                category="Threat Intimidation",
            ))
        elif threat_matches:
            findings.append(Finding(
                title="Financial Threat Language Detected",
                description="The text contains threats of financial penalties or legal action to coerce the recipient.",
                severity=SeverityLevel.high,
                evidence=threat_matches[0],
                category="Threat Intimidation",
            ))

        # 4. Impersonation of authorities
        impersonation_matches = []
        for pattern in IMPERSONATION_KEYWORDS:
            m = re.search(pattern, text)
            if m:
                impersonation_matches.append(m.group(0))
        if impersonation_matches:
            findings.append(Finding(
                title="Authority Impersonation Detected",
                description="The text mentions government agencies or law enforcement, which could indicate an authority impersonation scam.",
                severity=SeverityLevel.high,
                evidence=f"Mentions: {', '.join(set(impersonation_matches[:4]))}",
                category="Impersonation",
            ))

        # 5. Fake prize / lottery
        prize_matches = []
        for pattern in FAKE_PRIZE_PATTERNS:
            m = re.search(pattern, text)
            if m:
                prize_matches.append(m.group(0))
        if prize_matches:
            findings.append(Finding(
                title="Lottery / Prize Scam Language",
                description="The text claims the recipient has won a prize or lottery. This is a common social engineering tactic.",
                severity=SeverityLevel.high,
                evidence=prize_matches[0],
                category="Lottery Scam",
            ))

        # 6. Job scam patterns
        for pattern in JOB_SCAM_PATTERNS:
            m = re.search(pattern, text)
            if m:
                findings.append(Finding(
                    title="Fake Job Offer Indicators",
                    description="The text contains patterns typical of fraudulent job offers promising unrealistic earnings.",
                    severity=SeverityLevel.medium,
                    evidence=m.group(0),
                    category="Job Scam",
                ))
                break

        # 7. Investment scam patterns
        for pattern in INVESTMENT_SCAM_PATTERNS:
            m = re.search(pattern, text)
            if m:
                findings.append(Finding(
                    title="Investment Scam Indicators",
                    description="The text promises guaranteed returns or risk-free investments, which are hallmarks of investment fraud.",
                    severity=SeverityLevel.high,
                    evidence=m.group(0),
                    category="Investment Scam",
                ))
                break

        # 8. URLs within text
        url_pattern = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
        urls_in_text = url_pattern.findall(text)
        for found_url in urls_in_text[:5]:
            url_findings = self.check_url(found_url)
            findings.extend(url_findings)

        return findings

    def check_domain(self, domain: str) -> List[Finding]:
        findings: List[Finding] = []
        clean_domain = domain.lower().lstrip("www.").split(":")[0]
        hostname = clean_domain.split(".")[0] if "." in clean_domain else clean_domain

        for brand, lookalikes in BRAND_LOOKALIKES.items():
            # Check if domain contains brand name but isn't the real domain
            if brand in clean_domain:
                real_domains = {
                    "google": "google.com", "facebook": "facebook.com",
                    "paypal": "paypal.com", "amazon": "amazon.com",
                    "microsoft": "microsoft.com", "apple": "apple.com",
                    "netflix": "netflix.com", "sbi": "onlinesbi.com",
                    "hdfc": "hdfcbank.com", "icici": "icicibank.com",
                    "paytm": "paytm.com", "irctc": "irctc.co.in",
                }
                if brand in real_domains:
                    official = real_domains[brand]
                    # If it contains the brand name but is not an official domain
                    if official not in clean_domain and not clean_domain.endswith(f".{official}"):
                        findings.append(Finding(
                            title=f"Potential {brand.title()} Brand Impersonation",
                            description=f"This domain uses the '{brand}' brand name but is not the official {official} domain. This may be a typosquatting or brand impersonation attempt.",
                            severity=SeverityLevel.high,
                            evidence=f"Domain: {domain}",
                            category="Brand Impersonation",
                        ))

            # Check for lookalike characters
            for lookalike in lookalikes:
                if lookalike in clean_domain:
                    findings.append(Finding(
                        title=f"Homograph / Typosquatting Detected: {brand.title()}",
                        description=f"The domain uses character substitution to appear as '{brand}'. This is a known phishing technique.",
                        severity=SeverityLevel.critical,
                        evidence=f"Detected pattern '{lookalike}' mimicking '{brand}'",
                        category="Typosquatting",
                    ))
                    break

        return findings
