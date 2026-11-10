from pydantic import BaseModel, HttpUrl, field_validator
from typing import Optional, List, Dict, Any, Literal
from datetime import datetime
from enum import Enum


class SeverityLevel(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Finding(BaseModel):
    title: str
    description: str
    severity: SeverityLevel
    evidence: Optional[str] = None
    category: str


class ScanRequest(BaseModel):
    url: Optional[str] = None
    text: Optional[str] = None


class ScanResponse(BaseModel):
    scan_id: str
    scan_type: str
    input_reference: Optional[str] = None
    timestamp: datetime
    risk_score: int
    threat_level: str
    findings: List[Finding]
    confidence: str
    status: str
    scan_duration_ms: int
    report_data: Optional[Dict[str, Any]] = None

    model_config = {"from_attributes": True}


class FileScanResponse(ScanResponse):
    file_hash: Optional[str] = None
    file_name: Optional[str] = None
    file_size: Optional[int] = None
    mime_type: Optional[str] = None


class ScanHistoryItem(BaseModel):
    scan_id: str
    scan_type: str
    input_reference: Optional[str] = None
    timestamp: datetime
    risk_score: int
    threat_level: str
    confidence: str
    status: str
    findings_count: int = 0

    model_config = {"from_attributes": True}


class DashboardStats(BaseModel):
    total_scans: int
    safe_count: int
    suspicious_count: int
    critical_count: int
    threat_distribution: Dict[str, int]
    recent_scans: List[ScanHistoryItem]
    risk_level_distribution: Dict[str, int]
    most_common_threats: List[Dict[str, Any]]


class QuizSubmitRequest(BaseModel):
    level: str
    answers: Dict[str, int]  # question_id -> chosen_option_index
    user_session: Optional[str] = None


class QuizSubmitResponse(BaseModel):
    score: int
    total: int
    percentage: float
    results: List[Dict[str, Any]]
    passed: bool
