from Constants import SAFE_DOMAIN_LIST


def check_whitelist(email, domain):

    risk_score = 0
    reasons = []

    # ✅ Always return something if email is invalid
    # if "@" not in email:
    #     risk_score = 100
    #     reasons.append("Invalid email format (missing @)")
    #     return risk_score, reasons

    # Extract domain safely
    parts = email.split("@")
    if len(parts) < 2:
        risk_score = 100
        reasons.append("Invalid email format (bad domain part)")
        return risk_score, reasons

    # Check whitelist
    if domain in [d.lower() for d in SAFE_DOMAIN_LIST]:
        reasons.append("Domain is in whitelist")
    else:
        risk_score += 100
        reasons.append(f"Domain '{domain}' is not in whitelist")

    # ✅ Always end with return
    return risk_score, reasons
