import re

# removes special characters and numbers from text
def preprocess_text(text):
    clean_text = re.sub(r"[^a-zA-Z0-9\s]", " ", text)
    clean_text = clean_text.lower().strip()

    return clean_text

def find_suspicious_keywords(text):

    suspicious_keywords = [
    "urgent","immediately","terminated","suspended","compromised","on hold","violation","verify",
    "login","password","security","locked","pay","overdue","action","transfer",
    "download","click","won","winner","free","gift","prize","congratulations",
    "selected","exclusive","dear Customer","favour","last chance","final call","last call","sexy",
    "hot","single","near you"
    ]

    count = 0
    found = []

    # Extract individual words from email text
    plain_text = preprocess_text(text)
    plain_text_list = plain_text.split(" ")

    # Find count of suspicious keywords and add into found list
    for word in plain_text_list:
        if word in suspicious_keywords:
            count += 1
            if word not in found:
                found.append(word)

    risk_score = 50 if count > 0 else 0
    
    if count == 0: 
        return False, risk_score, {"count": count, "found": found}
    else:
        return True, risk_score, {"count": count, "found": found}

def check_whitelist(email):

    safe_domains = [
        'gmail.com', 'outlook.com', 'neo.email', 'yahoo.com',
        'proton.me', 'protonmail.com', 'icloud.com', 'zohomail.com',
        'aol.com', 'tuta.com', 'tutanota.com', 'mailfence.com'
    ]
    
    risk_score = 0

    # Check if email contains @
    if "@" not in email: risk_score += 100, "invalid email"

    # Extract domain
    domain = email.split("@")[1]

    # Check if domain is in safe list
    if domain.lower() in [d.lower() for d in safe_domains]:
        risk_score = 0 
        is_safe = True
    else:
        risk_score += 100
        is_safe = False

    return risk_score, is_safe, domain.lower()