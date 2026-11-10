import os
import json
import random
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models.scan import QuizResult
from app.schemas.scan import QuizSubmitRequest, QuizSubmitResponse

router = APIRouter(prefix="/quiz", tags=["Cyber Security Quiz"])

QUIZ_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "data",
    "quiz_questions.json"
)


def _load_questions() -> List[Dict[str, Any]]:
    if not os.path.exists(QUIZ_FILE):
        return []
    with open(QUIZ_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


@router.get("/questions")
async def get_quiz_questions(
    level: str = Query("beginner", pattern="^(beginner|intermediate|advanced)$"),
    count: int = Query(10, ge=1, le=20)
):
    all_q = _load_questions()
    filtered = [q for q in all_q if q.get("level", "").lower() == level.lower()]

    if not filtered:
        filtered = all_q

    sample = random.sample(filtered, min(count, len(filtered)))

    # Return questions with options but WITHOUT correct_answer to prevent client cheating
    sanitized = []
    for q in sample:
        sanitized.append({
            "id": q["id"],
            "level": q["level"],
            "question": q["question"],
            "options": q["options"],
            "category": q.get("category", "Cyber Safety")
        })

    return sanitized


@router.post("/submit")
async def submit_quiz_answers(submission: Dict[str, Any], db: Session = Depends(get_db)):
    """
    Accepts:
    {
      "level": "beginner",
      "answers": [{"question_id": "beg-01", "selected_answer": 2}, ...]
      OR
      "answers": {"beg-01": 2, ...}
    }
    """
    raw_answers = submission.get("answers", [])
    level = submission.get("level", "beginner")
    user_session = submission.get("user_session", str(uuid.uuid4()))

    # Normalize answers map: question_id -> chosen_idx
    ans_map = {}
    if isinstance(raw_answers, list):
        for item in raw_answers:
            if isinstance(item, dict) and "question_id" in item:
                ans_map[item["question_id"]] = item.get("selected_answer", -1)
    elif isinstance(raw_answers, dict):
        ans_map = raw_answers

    all_q = {q["id"]: q for q in _load_questions()}

    score = 0
    total = len(ans_map)
    results = []

    for qid, user_choice in ans_map.items():
        q_data = all_q.get(qid)
        if not q_data:
            continue

        correct_choice = q_data["correct_answer"]
        is_correct = (user_choice == correct_choice)
        if is_correct:
            score += 1

        results.append({
            "question_id": qid,
            "question": q_data["question"],
            "options": q_data["options"],
            "selected_answer": user_choice,
            "correct_answer": correct_choice,
            "is_correct": is_correct,
            "explanation": q_data.get("explanation", ""),
            "category": q_data.get("category", "")
        })

    percentage = round((score / total * 100), 1) if total > 0 else 0.0
    passed = percentage >= 70.0

    # Save to database
    record = QuizResult(
        id=str(uuid.uuid4()),
        user_session=user_session,
        level=level,
        score=score,
        total_questions=total,
        completed_at=datetime.utcnow()
    )
    db.add(record)
    db.commit()

    return {
        "score": score,
        "total": total,
        "percentage": percentage,
        "passed": passed,
        "results": results
    }


@router.get("/stats")
async def get_quiz_stats(db: Session = Depends(get_db)):
    total_taken = db.query(QuizResult).count()
    if total_taken == 0:
        return {
            "total_quizzes_taken": 0,
            "average_score_percentage": 0,
            "passed_count": 0,
            "pass_rate_percentage": 0
        }

    results = db.query(QuizResult).all()
    percentages = [(r.score / r.total_questions * 100) for r in results if r.total_questions > 0]
    passed = [p for p in percentages if p >= 70.0]

    avg_score = round(sum(percentages) / len(percentages), 1) if percentages else 0

    return {
        "total_quizzes_taken": total_taken,
        "average_score_percentage": avg_score,
        "passed_count": len(passed),
        "pass_rate_percentage": round((len(passed) / total_taken * 100), 1)
    }
