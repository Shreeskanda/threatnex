import os
import uuid
import json
import time
import hashlib
import aiofiles
from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.scan import ScanRecord
from app.schemas.scan import ScanRequest, ScanResponse, FileScanResponse, Finding, SeverityLevel
from app.engines.website_inspector import WebsiteInspector
from app.engines.file_analyzer import FileAnalyzer
from app.engines.image_analyzer import ImageAnalyzer
from app.engines.risk_scorer import RiskScorer
from app.engines.threat_intel import ThreatIntelligence
from app.detectors.content_analysis import ContentAnalyzer
from app.detectors.phishing import PhishingDetector

router = APIRouter(prefix="/scan", tags=["Scanning"])

UPLOAD_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

MAX_FILE_SIZE = 15 * 1024 * 1024  # 15 MB

website_inspector = WebsiteInspector()
file_analyzer = FileAnalyzer()
image_analyzer = ImageAnalyzer()
risk_scorer = RiskScorer()
threat_intel = ThreatIntelligence()
content_analyzer = ContentAnalyzer()
phishing_detector = PhishingDetector()


def _serialize_findings(findings: List[Finding]) -> str:
    return json.dumps([f.model_dump() for f in findings])


def _deserialize_findings(findings_str: str) -> List[Finding]:
    if not findings_str:
        return []
    try:
        data = json.loads(findings_str)
        return [Finding(**item) for item in data]
    except Exception:
        return []


@router.post("/url", response_model=ScanResponse)
async def scan_url_endpoint(req: ScanRequest, db: Session = Depends(get_db)):
    if not req.url or not req.url.strip():
        raise HTTPException(status_code=400, detail="A valid URL is required.")

    url = req.url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    start_time = time.time()
    scan_id = str(uuid.uuid4())

    # 1. Threat Intelligence Lookup
    intel_findings, api_status = await threat_intel.check_url(url)

    # 2. Comprehensive Website & Code Inspection
    site_findings, metadata = await website_inspector.inspect(url)

    all_findings = intel_findings + site_findings
    metadata["api_status"] = api_status

    # 3. Calculate Risk Score
    score, threat_level, confidence = risk_scorer.calculate(all_findings, scan_type="url")
    duration_ms = int((time.time() - start_time) * 1000)

    # 4. Save to Database
    record = ScanRecord(
        id=scan_id,
        scan_type="url",
        input_reference=url,
        file_hash=None,
        timestamp=datetime.utcnow(),
        risk_score=score,
        threat_level=threat_level,
        findings=_serialize_findings(all_findings),
        confidence=confidence,
        status="completed",
        scan_duration_ms=duration_ms,
        report_data=json.dumps(metadata)
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    return ScanResponse(
        scan_id=scan_id,
        scan_type="url",
        input_reference=url,
        timestamp=record.timestamp,
        risk_score=score,
        threat_level=threat_level,
        findings=all_findings,
        confidence=confidence,
        status="completed",
        scan_duration_ms=duration_ms,
        report_data=metadata
    )


@router.post("/file", response_model=FileScanResponse)
async def scan_file_endpoint(file: UploadFile = File(...), db: Session = Depends(get_db)):
    start_time = time.time()
    scan_id = str(uuid.uuid4())
    filename = file.filename or "uploaded_file"

    # Save to isolated temporary file with size validation
    temp_path = os.path.join(UPLOAD_DIR, f"{scan_id}_{filename}")
    total_size = 0
    hasher = hashlib.sha256()

    try:
        async with aiofiles.open(temp_path, "wb") as f:
            while chunk := await file.read(1024 * 64):
                total_size += len(chunk)
                if total_size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"Uploaded file exceeds maximum limit of {MAX_FILE_SIZE // (1024*1024)}MB."
                    )
                hasher.update(chunk)
                await f.write(chunk)
    except HTTPException:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise
    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise HTTPException(status_code=500, detail=f"File save error: {str(e)}")

    file_hash = hasher.hexdigest()
    mime_type = file.content_type or "application/octet-stream"

    # Route by MIME type / extension: if image, use image_analyzer; otherwise file_analyzer
    is_image = any(filename.lower().endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif"]) or "image" in mime_type

    if is_image:
        findings, metadata = image_analyzer.analyze(temp_path)
        scan_type = "image"
    else:
        findings, metadata = file_analyzer.analyze(temp_path, mime_type, filename)
        scan_type = "file"

    score, threat_level, confidence = risk_scorer.calculate(findings, scan_type=scan_type)
    duration_ms = int((time.time() - start_time) * 1000)

    # Secure cleanup of temporary file
    try:
        if os.path.exists(temp_path):
            os.remove(temp_path)
    except Exception:
        pass

    metadata["file_name"] = filename
    metadata["file_size"] = total_size
    metadata["mime_type"] = mime_type
    metadata["file_hash"] = file_hash

    record = ScanRecord(
        id=scan_id,
        scan_type=scan_type,
        input_reference=filename,
        file_hash=file_hash,
        timestamp=datetime.utcnow(),
        risk_score=score,
        threat_level=threat_level,
        findings=_serialize_findings(findings),
        confidence=confidence,
        status="completed",
        scan_duration_ms=duration_ms,
        report_data=json.dumps(metadata)
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    return FileScanResponse(
        scan_id=scan_id,
        scan_type=scan_type,
        input_reference=filename,
        timestamp=record.timestamp,
        risk_score=score,
        threat_level=threat_level,
        findings=findings,
        confidence=confidence,
        status="completed",
        scan_duration_ms=duration_ms,
        report_data=metadata,
        file_hash=file_hash,
        file_name=filename,
        file_size=total_size,
        mime_type=mime_type
    )


@router.post("/image", response_model=FileScanResponse)
async def scan_image_endpoint(file: UploadFile = File(...), db: Session = Depends(get_db)):
    return await scan_file_endpoint(file=file, db=db)


@router.post("/text", response_model=ScanResponse)
async def scan_text_endpoint(req: ScanRequest, db: Session = Depends(get_db)):
    if not req.text or not req.text.strip():
        raise HTTPException(status_code=400, detail="Text content cannot be empty.")

    start_time = time.time()
    scan_id = str(uuid.uuid4())
    raw_text = req.text.strip()

    # 1. Analyze text for scam/intimidation/OTP/financial pressure
    text_findings = content_analyzer.analyze_text(raw_text)

    # 2. Analyze any embedded URLs in text
    phish_findings = phishing_detector.check_text(raw_text)

    all_findings = text_findings + phish_findings

    score, threat_level, confidence = risk_scorer.calculate(all_findings, scan_type="text")
    duration_ms = int((time.time() - start_time) * 1000)

    metadata = {
        "text_preview": raw_text[:200],
        "character_count": len(raw_text),
        "word_count": len(raw_text.split())
    }

    record = ScanRecord(
        id=scan_id,
        scan_type="text",
        input_reference=raw_text[:50] + ("..." if len(raw_text) > 50 else ""),
        file_hash=None,
        timestamp=datetime.utcnow(),
        risk_score=score,
        threat_level=threat_level,
        findings=_serialize_findings(all_findings),
        confidence=confidence,
        status="completed",
        scan_duration_ms=duration_ms,
        report_data=json.dumps(metadata)
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    return ScanResponse(
        scan_id=scan_id,
        scan_type="text",
        input_reference=record.input_reference,
        timestamp=record.timestamp,
        risk_score=score,
        threat_level=threat_level,
        findings=all_findings,
        confidence=confidence,
        status="completed",
        scan_duration_ms=duration_ms,
        report_data=metadata
    )


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan_result_endpoint(scan_id: str, db: Session = Depends(get_db)):
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    findings = _deserialize_findings(record.findings)
    report_data = json.loads(record.report_data) if record.report_data else {}

    return ScanResponse(
        scan_id=record.id,
        scan_type=record.scan_type,
        input_reference=record.input_reference,
        timestamp=record.timestamp,
        risk_score=record.risk_score,
        threat_level=record.threat_level,
        findings=findings,
        confidence=record.confidence,
        status=record.status,
        scan_duration_ms=record.scan_duration_ms,
        report_data=report_data
    )
