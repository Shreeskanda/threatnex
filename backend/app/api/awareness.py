import os
import json
from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/awareness", tags=["Cyber Awareness"])

AWARENESS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "data",
    "awareness_content.json"
)


def _load_awareness_data() -> List[Dict[str, Any]]:
    if not os.path.exists(AWARENESS_FILE):
        return []
    with open(AWARENESS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


@router.get("/categories")
async def get_awareness_categories():
    data = _load_awareness_data()
    summary = []
    for item in data:
        summary.append({
            "id": item.get("id"),
            "title": item.get("title"),
            "slug": item.get("slug"),
            "icon": item.get("icon", "ShieldAlert"),
            "description": item.get("description"),
            "severity_level": item.get("severity_level", "high")
        })
    return summary


@router.get("/{slug}")
async def get_awareness_by_slug(slug: str):
    data = _load_awareness_data()
    for item in data:
        if item.get("slug") == slug or item.get("id") == slug:
            return item

    raise HTTPException(status_code=404, detail=f"Cyber awareness category '{slug}' not found.")
