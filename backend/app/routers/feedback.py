from fastapi import APIRouter
from pydantic import BaseModel
from app.db.database import scans_collection, feedback_collection
from datetime import datetime

router = APIRouter()

class FeedbackInput(BaseModel):
    scan_id: str
    user_verdict: str

@router.post("")
def submit_feedback(data: FeedbackInput):
    feedback_collection.insert_one({
        "scan_id": data.scan_id,
        "user_verdict": data.user_verdict,
        "timestamp": datetime.utcnow()
    })
    return {"status": "received"}