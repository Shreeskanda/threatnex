import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, Text, Float
from app.database import Base


class ScanRecord(Base):
    __tablename__ = "scan_records"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_type = Column(String, nullable=False)          # url | file | image | text
    input_reference = Column(String, nullable=True)     # URL or filename
    file_hash = Column(String, nullable=True)           # SHA-256 of uploaded file
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    risk_score = Column(Integer, default=0)
    threat_level = Column(String, default="UNKNOWN")
    findings = Column(Text, nullable=True)              # JSON
    confidence = Column(String, default="LOW")
    status = Column(String, default="processing")       # processing | completed | error
    scan_duration_ms = Column(Integer, default=0)
    report_data = Column(Text, nullable=True)           # Full report JSON


class QuizResult(Base):
    __tablename__ = "quiz_results"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_session = Column(String, nullable=True)
    level = Column(String, nullable=False)              # beginner | intermediate | advanced
    score = Column(Integer, default=0)
    total_questions = Column(Integer, default=0)
    completed_at = Column(DateTime, default=datetime.utcnow)
