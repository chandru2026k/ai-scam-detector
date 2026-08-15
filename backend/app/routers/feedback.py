from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()

class FeedbackInput(BaseModel):
    scan_id: str
    user_verdict: str

@router.post("")
def submit_feedback(data: FeedbackInput):
    return {"status": "received"}