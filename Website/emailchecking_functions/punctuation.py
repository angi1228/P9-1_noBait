def check_punctuation(content: str):
    reasons, score = [], 0.0
    if content.count('!') > 3:
        score += 0.5; reasons.append("Excessive use of exclamation marks")
    return score, reasons