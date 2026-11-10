import os
import io
import zipfile
import pytest
from app.engines.file_analyzer import FileAnalyzer
from app.engines.image_analyzer import ImageAnalyzer
from app.schemas.scan import SeverityLevel


@pytest.fixture
def file_analyzer():
    return FileAnalyzer()


@pytest.fixture
def image_analyzer():
    return ImageAnalyzer()


def test_zip_path_traversal_detection(file_analyzer, tmp_path):
    # Create a test zip file containing path traversal
    zip_path = os.path.join(tmp_path, "slip_test.zip")
    with zipfile.ZipFile(zip_path, 'w') as zf:
        zf.writestr("../../etc/passwd", "root:x:0:0")
        zf.writestr("safe_file.txt", "Hello world")

    findings, meta = file_analyzer.analyze(zip_path, "application/zip", "slip_test.zip")
    assert any("traversal" in f.title.lower() or "zip slip" in f.title.lower() for f in findings)


def test_zip_executable_detection(file_analyzer, tmp_path):
    # Create a zip containing an executable script
    zip_path = os.path.join(tmp_path, "dropper.zip")
    with zipfile.ZipFile(zip_path, 'w') as zf:
        zf.writestr("invoice.pdf.exe", b"MZ\x90\x00")
        zf.writestr("script.vbs", "WScript.Echo 'test'")

    findings, meta = file_analyzer.analyze(zip_path, "application/zip", "dropper.zip")
    crit = [f for f in findings if f.severity == SeverityLevel.critical]
    assert len(crit) > 0
    assert any("executable" in f.title.lower() or "payload" in f.title.lower() for f in crit)


def test_docx_macro_instruction_detection(file_analyzer, tmp_path):
    import docx
    doc_path = os.path.join(tmp_path, "invoice.docx")
    doc = docx.Document()
    doc.add_heading("Confidential Security Clearance", 0)
    doc.add_paragraph("ATTENTION: This document is encrypted in Protected View. Please click 'Enable Content' and 'Enable Macro' on the yellow bar above to verify your signature.")
    doc.save(doc_path)

    findings, meta = file_analyzer.analyze(doc_path, "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "invoice.docx")
    assert any("macro" in f.title.lower() for f in findings)


def test_pptx_link_and_text_analysis(file_analyzer, tmp_path):
    from pptx import Presentation
    prs_path = os.path.join(tmp_path, "presentation.pptx")
    prs = Presentation()
    slide = prs.slides.add_slide(prs.slide_layouts[0])
    slide.shapes.title.text = "Corporate Annual Review"
    slide.shapes.placeholders[1].text = "Visit http://phishing-site-verify.xyz to confirm attendance."
    prs.save(prs_path)

    findings, meta = file_analyzer.analyze(prs_path, "application/vnd.openxmlformats-officedocument.presentationml.presentation", "presentation.pptx")
    assert meta["slides_count"] == 1


def test_pdf_creation_and_inspection(file_analyzer, tmp_path):
    from reportlab.pdfgen import canvas
    pdf_path = os.path.join(tmp_path, "test.pdf")
    c = canvas.Canvas(pdf_path)
    c.drawString(100, 750, "Urgent Notice: Transfer your bank account funds to avoid arrest.")
    c.save()

    findings, meta = file_analyzer.analyze(pdf_path, "application/pdf", "test.pdf")
    assert meta["pdf_pages"] == 1


def test_image_qr_code_detection(image_analyzer, tmp_path):
    import qrcode
    img_path = os.path.join(tmp_path, "test_qr.png")
    qr = qrcode.QRCode()
    qr.add_data("https://sbi-fake-kyc.xyz/verify-otp")
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(img_path)

    findings, meta = image_analyzer.analyze(img_path)
    assert meta["has_qr_code"] is True
    assert "fake-kyc" in meta["decoded_qr_data"]
