import uuid
from datetime import datetime
from fastapi import APIRouter
from pydantic import BaseModel
from app.risk_engine.engine import compute_risk_score
from app.db.database import scans_collection

router = APIRouter()

class EmailScan(BaseModel):
    subject: str
    sender: str
    body: str

class UrlScan(BaseModel):
    url: str

class SmsScan(BaseModel):
    text: str
    sender: str

# TEMPORARY mock versions of B and C's functions until they hand off the real ones
def fake_classify_text(text: str) -> dict:
    return {"is_scam_prob": 0.7, "signals": ["Urgency language detected"]}

def fake_check_url(url: str) -> dict:
    return {"flagged": True, "reputation_score": 60, "signals": ["Domain registered recently"]}

def save_scan(scan_type: str, input_data: dict, result: dict) -> str:
    scan_id = str(uuid.uuid4())
    scans_collection.insert_one({
        "scan_id": scan_id,
        "scan_type": scan_type,
        "input": input_data,
        "result": result,
        "timestamp": datetime.utcnow()
    })
    result["scan_id"] = scan_id
    return result

@router.post("/email")
def scan_email(data: EmailScan):
    ml_result = fake_classify_text(data.subject + " " + data.body)
    intel_result = fake_check_url(data.sender)
    result = compute_risk_score(ml_result, intel_result)
    return save_scan("email", data.dict(), result)

@router.post("/url")
def scan_url(data: UrlScan):
    intel_result = fake_check_url(data.url)
    ml_result = {"is_scam_prob": 0, "signals": []}
    result = compute_risk_score(ml_result, intel_result)
    return save_scan("url", data.dict(), result)

@router.post("/sms")
def scan_sms(data: SmsScan):
    ml_result = fake_classify_text(data.text)
    intel_result = {"flagged": False, "reputation_score": 0, "signals": []}
    result = compute_risk_score(ml_result, intel_result)
    return save_scan("sms", data.dict(), result)

@router.post("/qr")
def scan_qr():
    ml_result = {"is_scam_prob": 0, "signals": []}
    intel_result = fake_check_url("http://example.com")
    result = compute_risk_score(ml_result, intel_result)
    result["decoded_url"] = "http://example.com"
    return save_scan("qr", {}, result)