import json
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database import get_db
from app.models.scan import ScanRecord
from app.schemas.scan import ScanHistoryItem

router = APIRouter(prefix="/history", tags=["Scan History"])


@router.get("")
async def get_history_endpoint(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    threat_level: Optional[str] = None,
    scan_type: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(ScanRecord)

    if search and search.strip():
        term = f"%{search.strip()}%"
        query = query.filter(ScanRecord.input_reference.ilike(term))

    if threat_level and threat_level.strip():
        query = query.filter(ScanRecord.threat_level == threat_level.strip())

    if scan_type and scan_type.strip():
        query = query.filter(ScanRecord.scan_type == scan_type.strip())

    total = query.count()
    offset = (page - 1) * limit
    records = query.order_by(desc(ScanRecord.timestamp)).offset(offset).limit(limit).all()

    items = []
    for r in records:
        f_count = 0
        if r.findings:
            try:
                f_count = len(json.loads(r.findings))
            except Exception:
                f_count = 0

        items.append({
            "scan_id": r.id,
            "scan_type": r.scan_type,
            "input_reference": r.input_reference,
            "timestamp": r.timestamp.isoformat(),
            "risk_score": r.risk_score,
            "threat_level": r.threat_level,
            "confidence": r.confidence,
            "status": r.status,
            "findings_count": f_count
        })

    pages = (total + limit - 1) // limit if limit > 0 else 1

    return {
        "items": items,
        "total": total,
        "page": page,
        "limit": limit,
        "pages": pages
    }


@router.delete("/{scan_id}")
async def delete_history_item(scan_id: str, db: Session = Depends(get_db)):
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    db.delete(record)
    db.commit()
    return {"message": "Scan record deleted successfully", "scan_id": scan_id}


@router.delete("")
async def clear_all_history(db: Session = Depends(get_db)):
    count = db.query(ScanRecord).delete()
    db.commit()
    return {"message": f"Successfully cleared {count} scan records."}
