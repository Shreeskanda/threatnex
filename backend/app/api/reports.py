import os
import io
import json
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.scan import ScanRecord
from app.schemas.scan import ScanResponse, Finding

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

router = APIRouter(tags=["Reports & Health"])


@router.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "THREATNEX Intelligence Engine",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/report/{scan_id}")
async def get_report_json(scan_id: str, db: Session = Depends(get_db)):
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan report not found.")

    findings = []
    if record.findings:
        try:
            findings = json.loads(record.findings)
        except Exception:
            findings = []

    report_data = {}
    if record.report_data:
        try:
            report_data = json.loads(record.report_data)
        except Exception:
            report_data = {}

    return {
        "scan_id": record.id,
        "scan_type": record.scan_type,
        "input_reference": record.input_reference,
        "file_hash": record.file_hash,
        "timestamp": record.timestamp.isoformat(),
        "risk_score": record.risk_score,
        "threat_level": record.threat_level,
        "confidence": record.confidence,
        "status": record.status,
        "scan_duration_ms": record.scan_duration_ms,
        "findings": findings,
        "metadata": report_data
    }


@router.get("/report/{scan_id}/pdf")
async def download_report_pdf(scan_id: str, db: Session = Depends(get_db)):
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    findings = []
    if record.findings:
        try:
            findings = json.loads(record.findings)
        except Exception:
            findings = []

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#1e3a8a')
    )
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#4b5563')
    )
    section_style = ParagraphStyle(
        'DocSection',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor('#0f172a')
    )
    body_style = ParagraphStyle(
        'DocBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=12,
        textColor=colors.HexColor('#1f2937')
    )
    bold_style = ParagraphStyle(
        'DocBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=12,
        textColor=colors.HexColor('#111827')
    )

    elements = []

    # Header
    elements.append(Paragraph("THREATNEX | SECURITY AUDIT REPORT", title_style))
    elements.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} | Platform: THREATNEX Enterprise v1.0", subtitle_style))
    elements.append(Spacer(1, 15))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#2563eb'), spaceBefore=5, spaceAfter=15))

    # Overview Table
    overview_data = [
        [Paragraph("Scan ID", bold_style), Paragraph(record.id, body_style)],
        [Paragraph("Scan Type", bold_style), Paragraph(record.scan_type.upper(), body_style)],
        [Paragraph("Target / Input", bold_style), Paragraph(str(record.input_reference or "N/A"), body_style)],
        [Paragraph("Risk Score", bold_style), Paragraph(f"<b>{record.risk_score} / 100</b>", body_style)],
        [Paragraph("Threat Level", bold_style), Paragraph(f"<b>{record.threat_level}</b>", body_style)],
        [Paragraph("Confidence", bold_style), Paragraph(record.confidence, body_style)],
        [Paragraph("Scan Duration", bold_style), Paragraph(f"{record.scan_duration_ms} ms", body_style)],
    ]
    if record.file_hash:
        overview_data.append([Paragraph("SHA-256 Hash", bold_style), Paragraph(record.file_hash, body_style)])

    overview_table = Table(overview_data, colWidths=[120, 410])
    overview_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('PADDING', (0, 0), (-1, -1), 5),
    ]))
    elements.append(overview_table)
    elements.append(Spacer(1, 20))

    # Technical Findings Section
    elements.append(Paragraph(f"Identified Findings ({len(findings)})", section_style))
    elements.append(Spacer(1, 10))

    if not findings:
        elements.append(Paragraph("No anomalous or malicious indicators were identified during the automated inspection of this target.", body_style))
    else:
        finding_rows = [[
            Paragraph("Severity", bold_style),
            Paragraph("Category", bold_style),
            Paragraph("Title & Evidence", bold_style)
        ]]
        for f in findings:
            sev = f.get("severity", "info").upper()
            title = f.get("title", "")
            desc = f.get("description", "")
            evid = f.get("evidence", "")
            cat = f.get("category", "General")

            desc_text = f"<b>{title}</b><br/>{desc}"
            if evid:
                desc_text += f"<br/><i>Evidence: {evid[:120]}</i>"

            finding_rows.append([
                Paragraph(sev, bold_style),
                Paragraph(cat, body_style),
                Paragraph(desc_text, body_style)
            ])

        findings_table = Table(finding_rows, colWidths=[70, 110, 350])
        findings_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e2e8f0')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        elements.append(findings_table)

    elements.append(Spacer(1, 25))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#94a3b8'), spaceBefore=5, spaceAfter=10))

    # Disclaimer footer
    disclaimer = (
        "<b>LEGAL & TECHNICAL DISCLAIMER:</b> THREATNEX operates automated static, heuristic, and behavioral inspection engines. "
        "Threat assessments reflect observable indicators at the time of scan and do not constitute an absolute guarantee of safety. "
        "For official government cyber fraud reporting in India, visit https://cybercrime.gov.in or dial national helpline 1930."
    )
    elements.append(Paragraph(disclaimer, ParagraphStyle('Disc', parent=styles['Normal'], fontSize=7.5, leading=10, textColor=colors.HexColor('#64748b'))))

    doc.build(elements)
    buffer.seek(0)
    pdf_bytes = buffer.getvalue()

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=threatnex-report-{scan_id}.pdf"}
    )
