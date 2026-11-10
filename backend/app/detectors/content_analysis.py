import re
from typing import List
from app.schemas.scan import Finding, SeverityLevel


OTP_REQUEST_PATTERNS = [
    re.compile(r"(?i)share\s+(your\s+)?otp"),
    re.compile(r"(?i)send\s+(me\s+)?the\s+otp"),
    re.compile(r"(?i)provide\s+(your\s+)?otp"),
    re.compile(r"(?i)enter\s+otp\s+here"),
    re.compile(r"(?i)verification\s+code\s+is\s+\d{4,8}"),
    re.compile(r"(?i)(otp|one[- ]time[- ]password)\s*:\s*\d{4,8}"),
]

PASSWORD_REQUEST_PATTERNS = [
    re.compile(r"(?i)share\s+your\s+password"),
    re.compile(r"(?i)provide\s+your\s+password"),
    re.compile(r"(?i)send\s+your\s+password"),
    re.compile(r"(?i)what\s+is\s+your\s+password"),
]

URGENCY_PATTERNS = [
    re.compile(r"(?i)(\burge?nt\b|\bimmediately\b|\bright\s+now\b)"),
    re.compile(r"(?i)(expire[sd]?\s+in\s+\d+\s+(minute|hour|day))"),
    re.compile(r"(?i)(last\s+chance|final\s+notice|action\s+required)"),
    re.compile(r"(?i)(your\s+(account|service)\s+(will\s+be\s+)?(suspended|disabled|terminated|blocked))"),
    re.compile(r"(?i)(respond\s+within\s+\d+\s+(minute|hour|day))"),
]

THREAT_PATTERNS = [
    re.compile(r"(?i)(arrest\s+warrant|will\s+be\s+arrested|police\s+will)"),
    re.compile(r"(?i)(FIR\s+(has\s+been\s+)?(filed|registered))"),
    re.compile(r"(?i)(court\s+summons?|appear\s+in\s+court|contempt\s+of\s+court)"),
    re.compile(r"(?i)(legal\s+action\s+will|criminal\s+complaint)"),
    re.compile(r"(?i)(penalty\s+of\s+(rs\.?|inr|rupees?)\s*[\d,]+)"),
    re.compile(r"(?i)(cyber\s+crime\s+(branch|department|cell))"),
]

FINANCIAL_PRESSURE_PATTERNS = [
    re.compile(r"(?i)send\s+(money|funds|cash)\s+(immediately|urgently|now)"),
    re.compile(r"(?i)transfer\s+(rs\.?|inr|rupees?)\s*[\d,]+"),
    re.compile(r"(?i)(payment\s+required|outstanding\s+(due|balance))"),
    re.compile(r"(?i)(fine\s+of|pay\s+a\s+fine)"),
    re.compile(r"(?i)(wire\s+transfer|money\s+order|prepaid\s+card)"),
]

PERSONAL_INFO_HARVEST_PATTERNS = [
    re.compile(r"(?i)share\s+(your\s+)?(aadhaar|aadhar)\s+(number|card)"),
    re.compile(r"(?i)share\s+(your\s+)?pan\s+(card|number)"),
    re.compile(r"(?i)(bank\s+account\s+number|ifsc\s+code).*share"),
    re.compile(r"(?i)send\s+(your\s+)?(credit|debit)\s+card\s+(details|number)"),
    re.compile(r"(?i)(date\s+of\s+birth|dob).*share"),
]

FAKE_AUTHORITY_PATTERNS = [
    re.compile(r"(?i)\b(I\s+am\s+(from|calling\s+from))\s+(RBI|CBI|police|court|TRAI|income\s+tax)"),
    re.compile(r"(?i)(official\s+notice\s+from|on\s+behalf\s+of\s+the\s+government)"),
    re.compile(r"(?i)(government\s+of\s+india\s+has\s+issued)"),
    re.compile(r"(?i)(calling\s+from\s+(cybercrime|cyber\s+crime|CID|CBI))"),
]

JOB_SCAM_PATTERNS = [
    re.compile(r"(?i)(earn\s+(rs\.?|inr|rupees?)?\s*[\d,]+\s+per\s+(day|week|month)\s+from\s+home)"),
    re.compile(r"(?i)(no\s+experience\s+(required|needed).*earn)"),
    re.compile(r"(?i)(part[- ]time.*guaranteed.*income)"),
    re.compile(r"(?i)registration\s+fee.*job"),
    re.compile(r"(?i)(join\s+(now|today).*earn)"),
]

INVESTMENT_SCAM_PATTERNS = [
    re.compile(r"(?i)(\d+%\s*(guaranteed|assured|fixed)\s+(return|profit|interest|yield))"),
    re.compile(r"(?i)(double\s+your\s+(money|investment)\s+in)"),
    re.compile(r"(?i)(no[- ]risk\s+invest|risk[- ]free\s+invest)"),
    re.compile(r"(?i)(guaranteed\s+profit\s+in\s+(crypto|bitcoin|forex|stock))"),
]

PRIZE_SCAM_PATTERNS = [
    re.compile(r"(?i)(you\s+(have\s+been\s+)?(selected|chosen)\s+(as\s+)?(lucky|winner))"),
    re.compile(r"(?i)(won\s+(rs\.?|inr|rupees?)?\s*[\d,]+\s+in\s+(lottery|lucky\s+draw))"),
    re.compile(r"(?i)(claim\s+(your\s+)?(prize|reward)\s+(within|immediately))"),
    re.compile(r"(?i)(lucky\s+draw\s+winner)"),
]

CSV_INJECTION_PATTERNS = [
    re.compile(r"^[=+\-@]"),                              # Formula injection
    re.compile(r"(?i)DDE\s*\("),                          # DDE injection
    re.compile(r"(?i)HYPERLINK\s*\("),                    # Hyperlink injection
    re.compile(r"(?i)cmd\s*/c"),                          # Command execution
    re.compile(r"(?i)(powershell|cmd\.exe|calc\.exe)"),  # Exec patterns
]


class ContentAnalyzer:

    def analyze_text(self, text: str) -> List[Finding]:
        findings: List[Finding] = []
        if not text:
            return findings

        # 1. OTP requests
        otp_matches = [p.search(text) for p in OTP_REQUEST_PATTERNS if p.search(text)]
        if otp_matches:
            findings.append(Finding(
                title="OTP Sharing Request Detected",
                description="The message requests sharing of an OTP. No legitimate organization or bank ever asks you to share your OTP.",
                severity=SeverityLevel.critical,
                evidence=otp_matches[0].group(0),
                category="Credential Harvesting",
            ))

        # 2. Password requests
        pwd_matches = [p.search(text) for p in PASSWORD_REQUEST_PATTERNS if p.search(text)]
        if pwd_matches:
            findings.append(Finding(
                title="Password Sharing Request Detected",
                description="The message requests sharing of a password, which is a hallmark of phishing and social engineering.",
                severity=SeverityLevel.critical,
                evidence=pwd_matches[0].group(0),
                category="Credential Harvesting",
            ))

        # 3. Urgency indicators
        urgency_matches = [p.search(text) for p in URGENCY_PATTERNS if p.search(text)]
        if len(urgency_matches) >= 2:
            findings.append(Finding(
                title="Multiple Urgency Indicators",
                description="Multiple urgency phrases detected. Scammers use artificial urgency to prevent victims from thinking clearly.",
                severity=SeverityLevel.high,
                evidence=f"{len(urgency_matches)} urgency indicators found",
                category="Social Engineering",
            ))
        elif urgency_matches:
            findings.append(Finding(
                title="Urgency Language Detected",
                description="Urgency language is used to pressure you into acting quickly without thinking.",
                severity=SeverityLevel.medium,
                evidence=urgency_matches[0].group(0),
                category="Social Engineering",
            ))

        # 4. Threats and intimidation
        threat_matches = [p.search(text) for p in THREAT_PATTERNS if p.search(text)]
        if len(threat_matches) >= 2:
            findings.append(Finding(
                title="Multiple Threat Indicators (Digital Arrest Pattern)",
                description="Multiple threat patterns detected. This matches the 'Digital Arrest' scam pattern where fraudsters impersonate law enforcement to intimidate victims.",
                severity=SeverityLevel.critical,
                evidence=f"{len(threat_matches)} threat phrases detected",
                category="Digital Arrest Scam",
            ))
        elif threat_matches:
            findings.append(Finding(
                title="Threat Language Detected",
                description="Threatening language found. Legitimate government agencies and courts do not threaten via SMS/WhatsApp.",
                severity=SeverityLevel.high,
                evidence=threat_matches[0].group(0),
                category="Threat Intimidation",
            ))

        # 5. Financial pressure
        fin_matches = [p.search(text) for p in FINANCIAL_PRESSURE_PATTERNS if p.search(text)]
        if fin_matches:
            findings.append(Finding(
                title="Financial Pressure Tactics Detected",
                description="The message pressures you to transfer money immediately, a classic fraud tactic.",
                severity=SeverityLevel.high,
                evidence=fin_matches[0].group(0),
                category="Financial Fraud",
            ))

        # 6. Personal info harvesting
        pii_matches = [p.search(text) for p in PERSONAL_INFO_HARVEST_PATTERNS if p.search(text)]
        if pii_matches:
            findings.append(Finding(
                title="Personal Information Harvesting Detected",
                description="The message requests sensitive personal information (Aadhaar, PAN, bank details). Never share these over phone/chat.",
                severity=SeverityLevel.critical,
                evidence=pii_matches[0].group(0),
                category="Identity Theft",
            ))

        # 7. Fake authority
        auth_matches = [p.search(text) for p in FAKE_AUTHORITY_PATTERNS if p.search(text)]
        if auth_matches:
            findings.append(Finding(
                title="Fake Authority Impersonation",
                description="The message claims to be from a government agency or law enforcement. This is a common impersonation scam.",
                severity=SeverityLevel.high,
                evidence=auth_matches[0].group(0),
                category="Impersonation",
            ))

        # 8. Job scams
        job_matches = [p.search(text) for p in JOB_SCAM_PATTERNS if p.search(text)]
        if job_matches:
            findings.append(Finding(
                title="Fake Job Offer Pattern",
                description="The message contains characteristics of fraudulent job offers promising unrealistic earnings.",
                severity=SeverityLevel.medium,
                evidence=job_matches[0].group(0),
                category="Job Scam",
            ))

        # 9. Investment scams
        inv_matches = [p.search(text) for p in INVESTMENT_SCAM_PATTERNS if p.search(text)]
        if inv_matches:
            findings.append(Finding(
                title="Investment Scam Indicators",
                description="The message promises guaranteed or unrealistic investment returns. All investments carry risk — 'guaranteed returns' are a red flag.",
                severity=SeverityLevel.high,
                evidence=inv_matches[0].group(0),
                category="Investment Fraud",
            ))

        # 10. Prize scams
        prize_matches = [p.search(text) for p in PRIZE_SCAM_PATTERNS if p.search(text)]
        if prize_matches:
            findings.append(Finding(
                title="Lottery / Prize Scam Language",
                description="The message claims you have won a prize. Legitimate lotteries do not notify winners via unsolicited messages.",
                severity=SeverityLevel.high,
                evidence=prize_matches[0].group(0),
                category="Lottery Scam",
            ))

        return findings

    def analyze_csv_content(self, content: str) -> List[Finding]:
        findings: List[Finding] = []
        if not content:
            return findings

        lines = content.splitlines()
        injection_cells = []
        dde_found = False

        for line_num, line in enumerate(lines[:500], 1):  # Check first 500 rows
            # Simple CSV split (not handling quoted fields perfectly but good enough for detection)
            cells = line.split(",")
            for col_num, cell in enumerate(cells):
                cell = cell.strip().strip('"')
                if not cell:
                    continue

                # Check formula injection
                if CSV_INJECTION_PATTERNS[0].match(cell):
                    injection_cells.append(f"Row {line_num}, Col {col_num + 1}: {cell[:40]}")

                # Check DDE
                if CSV_INJECTION_PATTERNS[1].search(cell):
                    dde_found = True

                # Check hyperlink injection
                if CSV_INJECTION_PATTERNS[2].search(cell):
                    injection_cells.append(f"Row {line_num}, Col {col_num + 1}: HYPERLINK() formula")

                # Check exec patterns
                for pat in CSV_INJECTION_PATTERNS[3:]:
                    if pat.search(cell):
                        injection_cells.append(f"Row {line_num}, Col {col_num + 1}: Exec pattern")
                        break

        if injection_cells:
            findings.append(Finding(
                title="CSV Formula Injection Detected",
                description=(
                    f"Found {len(injection_cells)} cell(s) containing formula injection patterns "
                    f"(starting with =, +, -, @). If opened in Excel or Google Sheets, these may execute "
                    f"commands or exfiltrate data."
                ),
                severity=SeverityLevel.high,
                evidence=f"Affected cells: {'; '.join(injection_cells[:5])}",
                category="CSV Injection",
            ))

        if dde_found:
            findings.append(Finding(
                title="DDE (Dynamic Data Exchange) Injection Detected",
                description=(
                    "DDE formula found in CSV. When opened in spreadsheet software, DDE formulas "
                    "can execute arbitrary commands on the victim's machine."
                ),
                severity=SeverityLevel.critical,
                evidence="DDE() formula pattern detected in CSV cell(s)",
                category="CSV Injection",
            ))

        return findings
