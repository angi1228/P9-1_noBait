import re
from Constants import SUSPICIOUS_KEYWORDS

# removes special characters that are not letter, digit or spaces from text
def preprocess_text(text):
    clean_text = re.sub(r"[^a-zA-Z0-9\s]", " ", text)
    clean_text = clean_text.lower().strip()
    return clean_text


def find_suspicious_keywords(text):
       
    count = 0
    found = []
    reasons = []

    # Extract words
    plain_text = preprocess_text(text)
    plain_text_list = plain_text.split(" ")

    # Count suspicious keywords
    for word in plain_text_list:
        if word in SUSPICIOUS_KEYWORDS:
            count += 1
            if word not in found:
                found.append(word)

    risk_score = 50 if count > 0 else 0

    if count > 0:
        reasons.append(f"Suspicious keywords found: {', '.join(found)}")
    else:
        reasons.append("No suspicious keywords found")

    # return score (int), reasons (list)
    return risk_score, reasons

