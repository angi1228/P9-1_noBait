def check_keywords(content: str):
    suspicious_keywords = [
        'urgent','verify','account','password','security','update','bank','login',
        'suspended','confirm','personal','information','click here','limited time',
        'offer','winner','prize','free','password expired','account suspended',
        'verify your account','unauthorized access','security alert','action required'
    ]
    reasons, found = [], []
    score, keyword_count = 0.0, 0
    lower = content.lower()

    for kw in suspicious_keywords:
        if kw in lower:
            found.append(kw)
            score += 0.5
            keyword_count += 1

    if found:
        reasons.append(f"Suspicious keywords detected: {', '.join(found[:5])}")
    return score, reasons, keyword_count