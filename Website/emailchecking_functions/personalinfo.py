def check_personal_info(content: str):
    reasons, score = [], 0.0
    lower = content.lower()
    sensitive = ["social security","credit card","ssn","password","username","date of birth","phone number"]
    if any(s in lower for s in sensitive):
        score += 2; reasons.append("Request for personal information")
    return score, reasons