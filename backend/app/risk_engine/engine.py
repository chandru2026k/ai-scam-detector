def compute_risk_score(ml_result: dict, intel_result: dict) -> dict:
    """
    Combines ML classifier output and threat-intel output into one
    explainable risk score (0-100).

    ml_result expected shape (from Member B):
        {"is_scam_prob": 0.0-1.0, "signals": [str, ...]}

    intel_result expected shape (from Member C):
        {"flagged": bool, "reputation_score": 0-100, "signals": [str, ...]}
    """
    factors = []

    # ML contributes up to 50 points, weighted by its confidence
    ml_prob = ml_result.get("is_scam_prob", 0)
    ml_points = round(ml_prob * 50)
    if ml_points > 0:
        factors.append({"reason": "AI language model flagged suspicious content", "weight": ml_points})

    # Threat intel contributes up to 50 points
    intel_points = 0
    if intel_result.get("flagged"):
        intel_points = round((intel_result.get("reputation_score", 0) / 100) * 50)
        factors.append({"reason": "Flagged by threat intelligence sources", "weight": intel_points})

    # Add individual named signals from each module as smaller factors
    for signal in ml_result.get("signals", []):
        factors.append({"reason": signal, "weight": 5})
    for signal in intel_result.get("signals", []):
        factors.append({"reason": signal, "weight": 5})

    risk_score = min(100, ml_points + intel_points)

    if risk_score >= 70:
        label = "high_risk"
    elif risk_score >= 30:
        label = "medium_risk"
    else:
        label = "low_risk"

    return {
        "risk_score": risk_score,
        "label": label,
        "factors": factors
    }
    