import re
import socket
import ipaddress
from typing import List, Tuple, Dict, Optional
from urllib.parse import urlparse
from app.schemas.scan import Finding, SeverityLevel

try:
    import dns.resolver
    import dns.rdatatype
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False


SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".work", ".click",
    ".link", ".top", ".pw", ".cc", ".su", ".biz", ".name",
    ".mobi", ".rocks", ".win", ".download", ".loan", ".review",
    ".stream", ".gdn", ".racing", ".date", ".trade", ".accountant",
    ".bid", ".party", ".science",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "buff.ly",
    "is.gd", "cli.gs", "dlvr.it", "short.ie", "tiny.cc", "lnkd.in",
    "rb.gy", "cutt.ly", "shorturl.at", "tiny.one", "rebrand.ly",
    "t.ly", "urlz.fr",
}

POPULAR_BRANDS = [
    "google", "facebook", "amazon", "netflix", "paypal", "microsoft",
    "apple", "bank", "gmail", "yahoo", "twitter", "instagram", "whatsapp",
    "youtube", "sbi", "hdfc", "icici", "axis", "kotak", "paytm",
    "phonepe", "gpay", "upi", "irctc", "uidai", "incometax", "gov", "india",
]

PRIVATE_IP_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local / AWS metadata
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

KNOWN_TEST_MALICIOUS = {
    "malware.testing.google.test",
    "phishing.test.example",
    "eicar.org",
}


class DomainIntelligence:

    def analyze(self, domain: str, url: str = "") -> Tuple[List[Finding], Dict]:
        findings: List[Finding] = []
        intel: Dict = {}

        clean_domain = domain.lower().strip()
        if clean_domain.startswith("www."):
            clean_domain = clean_domain[4:]

        # Remove port
        if ":" in clean_domain:
            clean_domain = clean_domain.split(":")[0]

        intel["domain"] = clean_domain

        # 1. IP address URL detection
        ip_findings, is_ip = self._check_ip_url(clean_domain)
        findings.extend(ip_findings)
        intel["is_ip_address"] = is_ip
        if is_ip:
            return findings, intel

        # 2. TLD risk assessment
        tld_findings, tld_info = self._check_tld(clean_domain)
        findings.extend(tld_findings)
        intel.update(tld_info)

        # 3. Subdomain analysis
        subdomain_findings, subdomain_info = self._analyze_subdomains(clean_domain)
        findings.extend(subdomain_findings)
        intel.update(subdomain_info)

        # 4. URL shortener check
        if clean_domain in URL_SHORTENERS:
            findings.append(Finding(
                title="URL Shortener Service",
                description=f"'{clean_domain}' is a URL shortening service. The actual destination is hidden.",
                severity=SeverityLevel.medium,
                evidence=f"Shortener: {clean_domain}",
                category="URL Obfuscation",
            ))
            intel["is_url_shortener"] = True
        else:
            intel["is_url_shortener"] = False

        # 5. Typosquatting check
        typosquatting_findings = self._check_typosquatting(clean_domain)
        findings.extend(typosquatting_findings)

        # 6. Known test malicious domains
        if clean_domain in KNOWN_TEST_MALICIOUS:
            findings.append(Finding(
                title="Known Test Malicious Domain",
                description=f"'{clean_domain}' is a known test/malicious domain used for security testing.",
                severity=SeverityLevel.critical,
                evidence=f"Domain in known malicious list: {clean_domain}",
                category="Threat Intelligence",
            ))

        # 7. DNS resolution check
        dns_findings, dns_info = self._check_dns(clean_domain)
        findings.extend(dns_findings)
        intel.update(dns_info)

        return findings, intel

    def _check_ip_url(self, domain: str) -> Tuple[List[Finding], bool]:
        findings = []
        ip_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
        if ip_pattern.match(domain):
            try:
                ip_obj = ipaddress.ip_address(domain)
                is_private = any(ip_obj in network for network in PRIVATE_IP_RANGES)
                severity = SeverityLevel.critical if is_private else SeverityLevel.high
                desc = (
                    "The URL uses a private/reserved IP address which could indicate an SSRF attempt or internal network access."
                    if is_private else
                    "The URL uses a raw IP address instead of a domain name. Legitimate websites use domain names."
                )
                findings.append(Finding(
                    title="IP Address URL Detected" + (" (Private IP)" if is_private else ""),
                    description=desc,
                    severity=severity,
                    evidence=f"IP: {domain}" + (" [Private/Reserved]" if is_private else ""),
                    category="Suspicious URL Structure",
                ))
                return findings, True
            except ValueError:
                pass
        return findings, False

    def _check_tld(self, domain: str) -> Tuple[List[Finding], Dict]:
        findings = []
        info = {}

        if HAS_TLDEXTRACT:
            extracted = tldextract.extract(domain)
            tld = f".{extracted.suffix}" if extracted.suffix else ""
            info["tld"] = tld
            info["registered_domain"] = extracted.registered_domain
            info["subdomain"] = extracted.subdomain
        else:
            parts = domain.rsplit(".", 2)
            tld = f".{parts[-1]}" if parts else ""
            info["tld"] = tld

        if info.get("tld") in SUSPICIOUS_TLDS:
            findings.append(Finding(
                title=f"High-Risk TLD: {info['tld']}",
                description=f"The TLD '{info['tld']}' is associated with a high volume of phishing and malware distribution.",
                severity=SeverityLevel.medium,
                evidence=f"Domain: {domain}, TLD: {info['tld']}",
                category="Suspicious Domain",
            ))

        return findings, info

    def _analyze_subdomains(self, domain: str) -> Tuple[List[Finding], Dict]:
        findings = []
        info = {}

        dot_count = domain.count(".")
        info["subdomain_depth"] = max(0, dot_count - 1)

        if dot_count > 3:
            findings.append(Finding(
                title="Excessive Subdomain Depth",
                description=f"Domain has {dot_count} levels. Legitimate services rarely exceed 3 subdomain levels. This technique is used to make domains look official.",
                severity=SeverityLevel.medium,
                evidence=f"Domain: {domain}",
                category="Suspicious Domain",
            ))

        return findings, info

    def _check_typosquatting(self, domain: str) -> List[Finding]:
        findings = []

        # Get the base domain name (without TLD)
        if HAS_TLDEXTRACT:
            extracted = tldextract.extract(domain)
            domain_name = extracted.domain.lower()
        else:
            parts = domain.rsplit(".", 1)
            domain_name = parts[0].lower() if parts else domain

        for brand in POPULAR_BRANDS:
            if brand == domain_name:
                continue  # Exact match, not typosquatting

            # Levenshtein distance approximation for typosquatting
            if len(brand) >= 4 and len(domain_name) >= 4:
                distance = self._levenshtein(brand, domain_name)
                if distance == 1 and brand not in domain_name:
                    findings.append(Finding(
                        title=f"Potential Typosquatting: '{brand}'",
                        description=f"Domain '{domain_name}' is very similar to the brand '{brand}' (edit distance: 1). This could be a typosquatting attempt.",
                        severity=SeverityLevel.high,
                        evidence=f"Target brand: {brand}, Detected domain part: {domain_name}",
                        category="Typosquatting",
                    ))

            # Check if brand is embedded but not at proper position
            if brand in domain_name and domain_name != brand:
                if not domain_name.startswith(brand) and not domain_name.endswith(brand):
                    findings.append(Finding(
                        title=f"Brand Name Embedded in Domain: '{brand}'",
                        description=f"The domain embeds the brand name '{brand}' in a suspicious position, which may confuse users.",
                        severity=SeverityLevel.medium,
                        evidence=f"Brand '{brand}' found inside domain part '{domain_name}'",
                        category="Brand Impersonation",
                    ))

        return findings

    def _check_dns(self, domain: str) -> Tuple[List[Finding], Dict]:
        findings = []
        info = {"dns_resolved": False, "dns_ips": []}

        if not HAS_DNSPYTHON:
            # Fallback to socket
            try:
                ips = socket.gethostbyname_ex(domain)[2]
                info["dns_resolved"] = True
                info["dns_ips"] = ips

                # Check if resolved IP is private
                for ip_str in ips:
                    try:
                        ip_obj = ipaddress.ip_address(ip_str)
                        if any(ip_obj in network for network in PRIVATE_IP_RANGES):
                            findings.append(Finding(
                                title="Domain Resolves to Private IP (SSRF Risk)",
                                description=f"The domain '{domain}' resolves to a private IP address '{ip_str}', which could indicate DNS rebinding or SSRF risk.",
                                severity=SeverityLevel.critical,
                                evidence=f"Resolved IP: {ip_str}",
                                category="SSRF / DNS Rebinding",
                            ))
                    except ValueError:
                        pass
            except socket.gaierror:
                info["dns_resolved"] = False
                findings.append(Finding(
                    title="Domain Does Not Resolve",
                    description=f"DNS resolution failed for '{domain}'. The domain may be newly registered, expired, or intentionally hidden.",
                    severity=SeverityLevel.low,
                    evidence=f"DNS lookup failed for: {domain}",
                    category="Domain Intelligence",
                ))
            return findings, info

        try:
            answers = dns.resolver.resolve(domain, "A")
            ips = [str(r) for r in answers]
            info["dns_resolved"] = True
            info["dns_ips"] = ips

            for ip_str in ips:
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    if any(ip_obj in network for network in PRIVATE_IP_RANGES):
                        findings.append(Finding(
                            title="Domain Resolves to Private IP (SSRF Risk)",
                            description=f"The domain resolves to a private IP address, which could indicate DNS rebinding or SSRF risk.",
                            severity=SeverityLevel.critical,
                            evidence=f"Resolved IP: {ip_str}",
                            category="SSRF / DNS Rebinding",
                        ))
                except ValueError:
                    pass
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            info["dns_resolved"] = False
            findings.append(Finding(
                title="Domain Does Not Resolve (NXDOMAIN)",
                description=f"DNS resolution returned NXDOMAIN for '{domain}'. This domain does not exist or has not propagated.",
                severity=SeverityLevel.low,
                evidence=f"NXDOMAIN: {domain}",
                category="Domain Intelligence",
            ))
        except dns.resolver.Timeout:
            info["dns_resolved"] = False
            findings.append(Finding(
                title="DNS Timeout",
                description=f"DNS resolution timed out for '{domain}'.",
                severity=SeverityLevel.info,
                evidence=f"DNS timeout: {domain}",
                category="Domain Intelligence",
            ))
        except Exception as e:
            info["dns_error"] = str(e)

        return findings, info

    def _levenshtein(self, s1: str, s2: str) -> int:
        """Compute Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            return self._levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]
