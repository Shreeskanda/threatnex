import json
from collections import Counter
from typing import Dict, Any, List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database import get_db
from app.models.scan import ScanRecord

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/stats")
async def get_dashboard_stats(db: Session = Depends(get_db)):
    records = db.query(ScanRecord).all()
    total_scans = len(records)

    safe_count = 0
    suspicious_count = 0
    critical_count = 0

    scan_type_counts = Counter()
    risk_level_counts = {
        "SAFE-LOOKING": 0,
        "LOW RISK": 0,
        "MODERATE RISK": 0,
        "HIGH RISK": 0,
        "CRITICAL RISK": 0,
    }
    threat_category_counts = Counter()

    for r in records:
        scan_type_counts[r.scan_type] += 1
        level = r.threat_level or "SAFE-LOOKING"
        if level in risk_level_counts:
            risk_level_counts[level] += 1
        else:
            risk_level_counts["SAFE-LOOKING"] += 1

        if level == "SAFE-LOOKING":
            safe_count += 1
        elif level in ["LOW RISK", "MODERATE RISK"]:
            suspicious_count += 1
        elif level in ["HIGH RISK", "CRITICAL RISK"]:
            critical_count += 1

        # Parse findings to get common categories
        if r.findings:
            try:
                findings_list = json.loads(r.findings)
                for f in findings_list:
                    cat = f.get("category", "General")
                    threat_category_counts[cat] += 1
            except Exception:
                pass

    # Recent scans (last 10)
    recent = db.query(ScanRecord).order_by(desc(ScanRecord.timestamp)).limit(10).all()
    recent_items = []
    for r in recent:
        recent_items.append({
            "scan_id": r.id,
            "scan_type": r.scan_type,
            "input_reference": r.input_reference,
            "timestamp": r.timestamp.isoformat(),
            "risk_score": r.risk_score,
            "threat_level": r.threat_level,
            "confidence": r.confidence,
            "status": r.status
        })

    # Format threat distribution for charts
    threat_distribution = [
        {"name": k.upper(), "value": v}
        for k, v in scan_type_counts.items()
    ]
    if not threat_distribution:
        threat_distribution = [
            {"name": "URL", "value": 0},
            {"name": "FILE", "value": 0},
            {"name": "IMAGE", "value": 0},
            {"name": "TEXT", "value": 0},
        ]

    # Format risk level distribution
    risk_distribution_list = [
        {"level": k, "count": v}
        for k, v in risk_level_counts.items()
    ]

    # Most common categories
    top_threats = [
        {"category": cat, "count": count}
        for cat, count in threat_category_counts.most_common(5)
    ]

    return {
        "total_scans": total_scans,
        "safe_count": safe_count,
        "suspicious_count": suspicious_count,
        "critical_count": critical_count,
        "threat_distribution": threat_distribution,
        "recent_scans": recent_items,
        "risk_level_distribution": risk_distribution_list,
        "most_common_threats": top_threats
    }
