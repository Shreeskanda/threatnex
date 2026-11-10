from typing import List, Tuple
from app.schemas.scan import Finding, SeverityLevel


SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 0,
}

SEVERITY_CAPS = {
    "critical": 50,
    "high": 35,
    "medium": 20,
    "low": 10,
    "info": 0,
}

THREAT_THRESHOLDS = [
    (80, "CRITICAL RISK"),
    (60, "HIGH RISK"),
    (40, "MODERATE RISK"),
    (20, "LOW RISK"),
    (0, "SAFE-LOOKING"),
]


class RiskScorer:

    def calculate(
        self,
        findings: List[Finding],
        scan_type: str = "url"
    ) -> Tuple[int, str, str]:
        """
        Calculate risk score, threat level, and confidence.
        Returns (score: int, threat_level: str, confidence: str)
        """
        if not findings:
            return 0, "SAFE-LOOKING", "LOW"

        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        accumulated = {k: 0 for k in severity_counts}

        for finding in findings:
            sev = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
            if sev in severity_counts:
                severity_counts[sev] += 1
                weight = SEVERITY_WEIGHTS[sev]
                cap = SEVERITY_CAPS[sev]
                accumulated[sev] = min(accumulated[sev] + weight, cap)

        raw_score = sum(accumulated.values())

        # Bonuses for combinations
        if severity_counts["critical"] >= 2 and severity_counts["high"] >= 1:
            raw_score = min(100, raw_score + 10)

        if severity_counts["critical"] >= 1 and severity_counts["medium"] >= 2:
            raw_score = min(100, raw_score + 5)

        # Scan-type adjustments
        if scan_type == "text" and severity_counts["critical"] >= 1:
            raw_score = min(100, raw_score + 5)

        score = max(0, min(100, raw_score))

        # Determine threat level
        threat_level = "SAFE-LOOKING"
        for threshold, level in THREAT_THRESHOLDS:
            if score >= threshold:
                threat_level = level
                break

        # Determine confidence
        total_significant = (
            severity_counts["critical"] +
            severity_counts["high"] +
            severity_counts["medium"]
        )
        total_findings = len(findings)

        if total_significant >= 2 or total_findings >= 5:
            confidence = "HIGH"
        elif total_findings >= 2:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"

        return score, threat_level, confidence
