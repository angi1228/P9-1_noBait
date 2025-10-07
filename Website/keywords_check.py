import Constants
from Constants import SUSPICIOUS_KEYWORDS

# removes special characters, whitespaces from text, converts to lowercase
def preprocess_text(text):
    clean_text = Constants.WORD_CLEANER.sub(' ', text)
    clean_text = clean_text.lower().strip()
    return clean_text


def find_suspicious_keywords(text):

    # Extract every word in the extracted email components
    plain_text = preprocess_text(text)
    plain_text_list = plain_text.split(" ")

    # Initialize 
    count = 0
    found = []
    
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
    return risk_score, found

def analyze_email(email_parts):
    
    # Combine header and body
    header_text = "".join(email_parts["headers"].values())
    body_text = email_parts.get("body", "")

    # Run keyword check on headers and body
    header_score, header_found = find_suspicious_keywords(header_text)
    body_score, body_found = find_suspicious_keywords(body_text)

    # Merge all found keywords and remove duplicates
    all_found = set(header_found + body_found)

    # Final risk score (maximum 50 if any keywords found)
    total_score = 50 if all_found else 0

    # Combine all reasons into one line
    reasons = f"Suspicious keywords found: {', '.join(sorted(all_found))}" if all_found else ""
    return total_score, reasons

