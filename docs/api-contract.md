# API Contract — AI Scam Detector

Base URL (local): http://localhost:8000

## POST /api/scan/email
Request: { "subject": string, "sender": string, "body": string }
Response: { "risk_score": int, "label": string, "factors": [{"reason": string, "weight": int}] }

## POST /api/scan/url
Request: { "url": string }
Response: { "risk_score": int, "label": string, "factors": [{"reason": string, "weight": int}] }

## POST /api/scan/sms
Request: { "text": string, "sender": string }
Response: { "risk_score": int, "label": string, "factors": [{"reason": string, "weight": int}] }

## POST /api/scan/qr
Request: (image upload, base64 - TBD by Member C)
Response: { "decoded_url": string, "risk_score": int, "label": string, "factors": [{"reason": string, "weight": int}] }

## POST /api/feedback
Request: { "scan_id": string, "user_verdict": "report_scam" | "mark_safe" }
Response: { "status": string }