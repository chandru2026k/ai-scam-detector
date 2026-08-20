import re
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

# Rule-based stand-ins for Member B's and Member C's functions.
# Same function signatures/return shapes they'll deliver later —
# swap the import when their real modules are ready, nothing else changes.

def fake_classify_text(text: str) -> dict:
    text_lower = text.lower()
    signals = []
    score = 0.0

    urgency_words = ["urgent", "immediately", "verify now", "act now", "suspended", "expire", "click here"]
    money_words = ["otp", "upi pin", "kyc", "bank account", "lottery", "winner", "prize", "refund"]
    threat_words = ["account will be closed", "legal action", "final warning", "unauthorized"]

    for word in urgency_words:
        if word in text_lower:
            signals.append(f"Urgency language detected: '{word}'")
            score += 0.15

    for word in money_words:
        if word in text_lower:
            signals.append(f"Financial/credential request detected: '{word}'")
            score += 0.2

    for word in threat_words:
        if word in text_lower:
            signals.append(f"Threatening language detected: '{word}'")
            score += 0.15

    score = min(1.0, score)
    return {"is_scam_prob": round(score, 2), "signals": signals[:4]}


def fake_check_url(url_or_email: str) -> dict:
    value = url_or_email.lower()
    signals = []
    reputation_score = 0

    suspicious_brands = ["paypal", "google", "amazon", "microsoft", "icici", "sbi", "hdfc"]
    for brand in suspicious_brands:
        if brand in value and f"{brand}.com" not in value and f"{brand}.in" not in value:
            signals.append(f"Possible lookalike domain of {brand}")
            reputation_score += 30

    if not value.startswith("https://") and "@" not in value:
        signals.append("Not using HTTPS")
        reputation_score += 15

    if re.search(r"\d{5,}", value):
        signals.append("Contains long numeric sequence (common in scam links)")
        reputation_score += 10

    if len(value) > 60:
        signals.append("Unusually long URL/address")
        reputation_score += 10

    flagged = reputation_score > 0
    return {
        "flagged": flagged,
        "reputation_score": min(100, reputation_score),
        "signals": signals[:3]
    }


def save_scan(scan_type: str, input_data: dict, result: dict) -> dict:
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