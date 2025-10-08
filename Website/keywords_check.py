import Constants
from Constants import SUSPICIOUS_KEYWORDS

def preprocess_text(text):
    # removes special characters, whitespaces from text, converts to lowercase
    clean_text = Constants.WORD_CLEANER.sub(' ', text)
    clean_text = clean_text.lower().strip()
    return clean_text


def find_suspicious_keywords(text):
    """This function runs through the extracted email text for any terms or phrases defined in the SUSPICIOUS_KEYWORDS list. It identifies both single 
    words (e.g., "urgent", "password") and multi-word phrases 
    (e.g., "limited time", "claim your refund") that are commonly used 
    in phishing or scam emails.
    """

    # Extract every word in the extracted email components
    plain_text = preprocess_text(text)
    plain_text_list = plain_text.split(" ")

    # Initialize 
    count = 0
    found = []
    reason = ""
    
    # Check through every word in the extracted email components
    for word in plain_text_list:
        if word in SUSPICIOUS_KEYWORDS:
            count += 1
            if word not in found:
                found.append(word)

    # Also check for suspicious phrases (multiple words)
    for phrase in SUSPICIOUS_KEYWORDS:
        if " " in phrase and phrase in plain_text:
            count += 1
            if phrase not in found:
                found.append(phrase)
                count += 1

    # Risk Scoring, maximum 50 if any found
    risk_score = 50 if count > 0 else 0

    # return score, list of found keywords 
    if found:
        reason = f"Quick keyword scan: {', '.join(sorted(found))}"
    else:
        reason = ""

    return risk_score, reason

