import httpx
import logging
from typing import List, Tuple, Dict, Optional
from app.schemas.scan import Finding, SeverityLevel
from app.config import settings

logger = logging.getLogger(__name__)

KNOWN_TEST_MALICIOUS_DOMAINS = {
    "malware.testing.google.test": "Google Safe Browsing test domain",
    "phishing.test.example": "Phishing test domain",
}


class ThreatIntelligence:

    def __init__(self):
        self.gsb_key = settings.GOOGLE_SAFE_BROWSING_API_KEY
        self.vt_key = settings.VIRUSTOTAL_API_KEY
        self.urlhaus_key = settings.URLHAUS_API_KEY
        self.phishtank_key = settings.PHISHTANK_API_KEY

    async def check_url(self, url: str) -> Tuple[List[Finding], Dict[str, str]]:
        """
        Check a URL against multiple threat intelligence sources.
        Returns (findings, api_status_dict).
        """
        findings: List[Finding] = []
        api_status: Dict[str, str] = {}

        # 1. Local test domain check
        local_findings = self._check_local_intel(url)
        findings.extend(local_findings)

        # 2. Google Safe Browsing
        gsb_findings, gsb_status = await self._check_gsb(url)
        findings.extend(gsb_findings)
        api_status["google_safe_browsing"] = gsb_status

        # 3. VirusTotal
        vt_findings, vt_status = await self._check_virustotal(url)
        findings.extend(vt_findings)
        api_status["virustotal"] = vt_status

        # 4. URLhaus
        urlhaus_findings, urlhaus_status = await self._check_urlhaus(url)
        findings.extend(urlhaus_findings)
        api_status["urlhaus"] = urlhaus_status

        # 5. PhishTank
        phishtank_findings, phishtank_status = await self._check_phishtank(url)
        findings.extend(phishtank_findings)
        api_status["phishtank"] = phishtank_status

        return findings, api_status

    def _check_local_intel(self, url: str) -> List[Finding]:
        findings = []
        url_lower = url.lower()
        for domain, reason in KNOWN_TEST_MALICIOUS_DOMAINS.items():
            if domain in url_lower:
                findings.append(Finding(
                    title="Known Malicious Domain (Local Intel)",
                    description=f"This URL contains a known test malicious domain: {domain}. Reason: {reason}",
                    severity=SeverityLevel.critical,
                    evidence=f"Matched: {domain}",
                    category="Threat Intelligence",
                ))
        return findings

    async def _check_gsb(self, url: str) -> Tuple[List[Finding], str]:
        if not self.gsb_key:
            return [], "skipped (no API key)"

        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.gsb_key}"
        payload = {
            "client": {"clientId": "cyber-sentinel", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE", "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(api_url, json=payload)
                resp.raise_for_status()
                data = resp.json()
                if data.get("matches"):
                    threats = data["matches"]
                    threat_types = list(set(t.get("threatType", "UNKNOWN") for t in threats))
                    return [Finding(
                        title=f"Google Safe Browsing: Threat Detected",
                        description=f"Google Safe Browsing identified this URL as threatening. Threat types: {', '.join(threat_types)}",
                        severity=SeverityLevel.critical,
                        evidence=f"Threat types: {', '.join(threat_types)}",
                        category="Threat Intelligence",
                    )], "checked"
                return [], "checked (clean)"
        except httpx.HTTPStatusError as e:
            logger.warning(f"GSB API error: {e}")
            return [], f"error ({e.response.status_code})"
        except Exception as e:
            logger.warning(f"GSB check failed: {e}")
            return [], "error (request failed)"

    async def _check_virustotal(self, url: str) -> Tuple[List[Finding], str]:
        if not self.vt_key:
            return [], "skipped (no API key)"

        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        headers = {"x-apikey": self.vt_key}
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(api_url, headers=headers)
                if resp.status_code == 404:
                    # Submit for analysis
                    submit_resp = await client.post(
                        "https://www.virustotal.com/api/v3/urls",
                        headers=headers,
                        data={"url": url}
                    )
                    if submit_resp.status_code == 200:
                        return [], "submitted (pending analysis)"
                    return [], "submitted"

                resp.raise_for_status()
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values()) if stats else 0

                if malicious >= 3:
                    return [Finding(
                        title="VirusTotal: Multiple Engines Flagged as Malicious",
                        description=f"VirusTotal analysis: {malicious}/{total} security engines flagged this URL as malicious.",
                        severity=SeverityLevel.critical,
                        evidence=f"Malicious: {malicious}, Suspicious: {suspicious}, Total engines: {total}",
                        category="Threat Intelligence",
                    )], "checked"
                elif malicious >= 1 or suspicious >= 3:
                    return [Finding(
                        title="VirusTotal: URL Flagged as Suspicious",
                        description=f"VirusTotal analysis: {malicious} malicious, {suspicious} suspicious detections out of {total} engines.",
                        severity=SeverityLevel.high,
                        evidence=f"Malicious: {malicious}, Suspicious: {suspicious}, Total: {total}",
                        category="Threat Intelligence",
                    )], "checked"

                return [], f"checked (clean: {total} engines)"
        except httpx.HTTPStatusError as e:
            logger.warning(f"VirusTotal API error: {e}")
            return [], f"error ({e.response.status_code})"
        except Exception as e:
            logger.warning(f"VirusTotal check failed: {e}")
            return [], "error (request failed)"

    async def _check_urlhaus(self, url: str) -> Tuple[List[Finding], str]:
        api_url = "https://urlhaus-api.abuse.ch/v1/url/"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(api_url, data={"url": url})
                resp.raise_for_status()
                data = resp.json()
                query_status = data.get("query_status", "")

                if query_status == "is_malware":
                    tags = data.get("tags", [])
                    return [Finding(
                        title="URLhaus: Malware URL Detected",
                        description=f"URLhaus (abuse.ch) has flagged this URL as a malware distribution point. Tags: {', '.join(tags) if tags else 'N/A'}",
                        severity=SeverityLevel.critical,
                        evidence=f"URLhaus status: {query_status}, Tags: {tags}",
                        category="Threat Intelligence",
                    )], "checked"
                elif query_status == "is_phishing":
                    return [Finding(
                        title="URLhaus: Phishing URL Detected",
                        description="URLhaus (abuse.ch) has flagged this URL as a phishing site.",
                        severity=SeverityLevel.critical,
                        evidence=f"URLhaus status: {query_status}",
                        category="Threat Intelligence",
                    )], "checked"

                return [], f"checked ({query_status or 'not listed'})"
        except Exception as e:
            logger.warning(f"URLhaus check failed: {e}")
            return [], "error (request failed)"

    async def _check_phishtank(self, url: str) -> Tuple[List[Finding], str]:
        api_url = "https://checkurl.phishtank.com/checkurl/"
        try:
            import urllib.parse
            payload = {
                "url": urllib.parse.quote(url, safe=""),
                "format": "json",
            }
            if self.phishtank_key:
                payload["app_key"] = self.phishtank_key

            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(api_url, data=payload)
                resp.raise_for_status()
                data = resp.json()
                results = data.get("results", {})

                if results.get("in_database") and results.get("valid"):
                    return [Finding(
                        title="PhishTank: Confirmed Phishing URL",
                        description="PhishTank has confirmed this is a phishing URL that has been reported and verified.",
                        severity=SeverityLevel.critical,
                        evidence=f"PhishTank phish ID: {results.get('phish_id', 'N/A')}",
                        category="Threat Intelligence",
                    )], "checked"
                elif results.get("in_database") and not results.get("valid"):
                    return [], "checked (phishing report invalid)"

                return [], "checked (not in database)"
        except Exception as e:
            logger.warning(f"PhishTank check failed: {e}")
            return [], "error (request failed)"
