def check_urgency(content: str):
    reasons, score = [], 0.0
    lower = content.lower()
    urgency_phrases = ["immediately","right away","as soon as possible","within 24 hours","urgent","time-sensitive"]
    count = sum(1 for u in urgency_phrases if u in lower)
    if count > 0:
        score += min(count * 0.5, 2)
        reasons.append("Urgency language detected")
    return score, reasons