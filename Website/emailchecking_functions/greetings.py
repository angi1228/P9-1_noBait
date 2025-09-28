def check_greetings(content: str):
    reasons, score = [], 0.0
    lower = content.lower()
    generic = ["dear user","dear customer","dear member","dear account holder","valued customer"]
    if any(g in lower for g in generic):
        score += 1; reasons.append("Generic greeting used")
    return score, reasons