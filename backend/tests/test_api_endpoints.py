import io
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "THREATNEX" in data["service"]


def test_scan_text_endpoint():
    payload = {
        "text": "URGENT NOTICE: Your SBI Bank account has been blocked. Click http://sbi-unblock-secure.xyz to update KYC and provide your 6-digit OTP."
    }
    response = client.post("/api/scan/text", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "scan_id" in data
    assert data["scan_type"] == "text"
    assert data["risk_score"] > 20
    assert len(data["findings"]) > 0


def test_scan_text_empty_rejected():
    response = client.post("/api/scan/text", json={"text": ""})
    assert response.status_code == 400


def test_scan_file_txt():
    content = b"URGENT: Income tax refund of Rs 45,000 pending. Transfer Rs 2,000 clearance fee immediately to account 123456."
    files = {"file": ("test_notice.txt", io.BytesIO(content), "text/plain")}
    response = client.post("/api/scan/file", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["file_name"] == "test_notice.txt"
    assert data["scan_type"] == "file"
    assert "findings" in data


def test_scan_file_csv_injection():
    csv_data = b"Date,Description,Amount\n2024-01-01,=cmd|' /C powershell evil.ps1'!A0,5000\n"
    files = {"file": ("financial_export.csv", io.BytesIO(csv_data), "text/csv")}
    response = client.post("/api/scan/file", files=files)
    assert response.status_code == 200
    data = response.json()
    findings = [f["title"] for f in data["findings"]]
    assert any("formula" in t.lower() or "csv" in t.lower() for t in findings)


def test_awareness_categories():
    response = client.get("/api/awareness/categories")
    assert response.status_code == 200
    categories = response.json()
    assert len(categories) == 24
    slugs = [c["slug"] for c in categories]
    assert "digital-arrest-scam" in slugs
    assert "phishing" in slugs
    assert "upi-fraud" in slugs
    assert "qr-code-scams" in slugs


def test_awareness_detail():
    response = client.get("/api/awareness/digital-arrest-scam")
    assert response.status_code == 200
    data = response.json()
    assert data["title"] == "Digital Arrest Scam"
    assert len(data["warning_signs"]) > 0
    assert "1930" in str(data["victim_steps"]) or "1930" in str(data["prevention_tips"])


def test_awareness_not_found():
    response = client.get("/api/awareness/non-existent-scam-xyz")
    assert response.status_code == 404


def test_quiz_questions():
    response = client.get("/api/quiz/questions?level=beginner&count=5")
    assert response.status_code == 200
    questions = response.json()
    assert len(questions) == 5
    for q in questions:
        assert "question" in q
        assert "options" in q
        assert len(q["options"]) == 4
        # correct_answer should NOT be leaked in question fetch
        assert "correct_answer" not in q


def test_quiz_submit():
    # Fetch questions first
    q_resp = client.get("/api/quiz/questions?level=beginner&count=2")
    q_data = q_resp.json()
    answers = [{"question_id": q["id"], "selected_answer": 0} for q in q_data]

    sub_resp = client.post("/api/quiz/submit", json={"level": "beginner", "answers": answers})
    assert sub_resp.status_code == 200
    result = sub_resp.json()
    assert "score" in result
    assert "total" in result
    assert "results" in result


def test_dashboard_stats():
    response = client.get("/api/dashboard/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_scans" in data
    assert "threat_distribution" in data
    assert "risk_level_distribution" in data


def test_report_pdf_generation():
    # First create a scan
    payload = {"text": "Suspicious link: http://bit.ly/claim-prize-now"}
    scan_resp = client.post("/api/scan/text", json=payload)
    scan_id = scan_resp.json()["scan_id"]

    # Download PDF
    pdf_resp = client.get(f"/api/report/{scan_id}/pdf")
    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["content-type"] == "application/pdf"
    assert pdf_resp.content.startswith(b"%PDF")
