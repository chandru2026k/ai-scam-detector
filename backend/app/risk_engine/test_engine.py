from app.risk_engine.engine import compute_risk_score

fake_ml = {"is_scam_prob": 0.9, "signals": ["Urgency language detected"]}
fake_intel = {"flagged": True, "reputation_score": 80, "signals": ["Domain registered 2 days ago"]}

result = compute_risk_score(fake_ml, fake_intel)
print(result)