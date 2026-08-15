from fastapi import APIRouter
from pydantic import BaseModel

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

@router.post("/email")
def scan_email(data: EmailScan):
    return {
        "risk_score": 72,
        "label": "high_risk",
        "factors": [
            {"reason": "Urgency language detected", "weight": 30},
            {"reason": "Suspicious sender domain", "weight": 42}
        ]
    }

@router.post("/url")
def scan_url(data: UrlScan):
    return {
        "risk_score": 15,
        "label": "low_risk",
        "factors": [{"reason": "Domain registered 5 years ago", "weight": 15}]
    }

@router.post("/sms")
def scan_sms(data: SmsScan):
    return {
        "risk_score": 85,
        "label": "high_risk",
        "factors": [{"reason": "Requests OTP", "weight": 50}, {"reason": "UPI keyword match", "weight": 35}]
    }

@router.post("/qr")
def scan_qr():
    return {
        "decoded_url": "http://example.com",
        "risk_score": 60,
        "label": "medium_risk",
        "factors": [{"reason": "Shortened URL", "weight": 60}]
    }