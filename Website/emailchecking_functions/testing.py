import re

# removes special characters that are not letter, digit or spaces from text
def preprocess_text(text):
    clean_text = re.sub(r"[^a-zA-Z0-9\s]", " ", text)
    clean_text = clean_text.lower().strip()
    return clean_text


def find_suspicious_keywords(text):
    suspicious_keywords = [
        "urgent", "immediately", "limited time", "account", "terminated", "suspended", "compromised", "on hold",
        "violation", "verify", "last warning", "final notice", "final call", "last call", "last chance",
        "important notice", "login", "password", "security", "locked", "pay", "overdue", "action required",
        "transfer", "claim your refund", "download", "click", "won", "winner", "free", "gift", "prize",
        "congratulations", "you have been selected", "claim your reward", "exclusive", "special offer",
        "no cost", "guaranteed", "dear customer", "favour", "sexy", "hot", "single", "near you", "meet singles",
        "dating", "babes", "babe", "nude", "naked", "money", "cash", "payment", "payments", "credit card", "loan",
        "offer", "deal", "sales", "earn", "membership","bank"
    ]
        
    count = 0
    found = []
    reasons = []

    # Extract words
    plain_text = preprocess_text(text)
    plain_text_list = plain_text.split(" ")

    # Count suspicious keywords
    for word in plain_text_list:
        if word in suspicious_keywords:
            count += 1
            if word not in found:
                found.append(word)

    risk_score = 50 if count > 0 else 0

    if count > 0:
        reasons.append(f"Suspicious keywords found: {', '.join(found)}")
    else:
        reasons.append("No suspicious keywords found")

    # ✅ return score (int), reasons (list)
    return risk_score, reasons


def check_whitelist(email):
    safe_domains = [
        "gmail.com", "outlook.com", "neo.email", "yahoo.com",
        "proton.me", "protonmail.com", "icloud.com", "zohomail.com",
        "aol.com", "tuta.com", "tutanota.com", "mailfence.com",
        "sit.singaporetech.edu.sg", "singaporetech.edu.sg", "mycompany.com"
    ]
    
    risk_score = 0
    reasons = []
    try:
    # Extract domain
        domain = email.split("@")[1].lower()

        # Check whitelist
        if domain in [d.lower() for d in safe_domains]:
            reasons.append("Domain is in whitelist")
        else:
            risk_score += 100
            reasons.append(f"Domain '{domain}' is not in whitelist")

        # ✅ return score (int), reasons (list)
        return risk_score, reasons

    except( IndexError,TypeError):
        print("Invalid email format")

# def check_whitelist(email):
    safe_domains = [
        "gmail.com", "outlook.com", "neo.email", "yahoo.com",
        "proton.me", "protonmail.com", "icloud.com", "zohomail.com",
        "aol.com", "tuta.com", "tutanota.com", "mailfence.com",
        "sit.singaporetech.edu.sg", "singaporetech.edu.sg", "mycompany.com"
    ]
    
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

    domain = parts[1].lower()

    # Check whitelist
    if domain in [d.lower() for d in safe_domains]:
        reasons.append("Domain is in whitelist")
    else:
        risk_score += 100
        reasons.append(f"Domain '{domain}' is not in whitelist")

    # ✅ Always end with return
    return risk_score, reasons


# Test Cases
if __name__ == "__main__":
    text1 = "Urgent! Please verify your account immediately to avoid suspension."
    text2 = "Hello friend, just checking in. How are you doing?"

    score1, reasons1 = find_suspicious_keywords(text1)
    print(score1, reasons1)

    score2, reasons2 = find_suspicious_keywords(text2)
    print(score2, reasons2)

    email1 = "user@gmail.com"
    email2 = "scammer@phishy.com"

    score3, reasons3 = check_whitelist(email1)
    print(score3, reasons3)

    score4, reasons4 = check_whitelist(email2)
    print(score4, reasons4)
