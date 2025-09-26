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
        "offer", "deal", "sales", "earn", "membership"
    ]
        
    #Initialize
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

    return {"is_suspicious": count > 0, "risk_score": risk_score, "count": count, "Words_found": found}

def check_whitelist(email):

    safe_domains = [
        "gmail.com", "outlook.com", "neo.email", "yahoo.com",
        "proton.me", "protonmail.com", "icloud.com", "zohomail.com",
        "aol.com", "tuta.com", "tutanota.com", "mailfence.com",
        "sit.singaporetech.edu.sg", "singaporetech.edu.sg", "mycompany.com"
    ]
    
    #Initialize
    is_safe = False
    risk_score = 0
    domain = None
    reason = ""

    # Extract domain
    domain = email.split("@")[1]

    # Check if domain is in safe list
    if domain.lower() in [d.lower() for d in safe_domains]:
        risk_score = 0 
        is_safe = True
        reason = "Domain is in whitelist"
    else:
        risk_score += 100
        is_safe = False
        reason = "Domain is not in whitelist"

    return {"is_safe": is_safe, "risk_score": risk_score, "domain": domain.lower(), "reason": reason}


#Test Codesss
if __name__ == "__main__":
    test_texts = [
        "Your account has been suspended. Please login immediately to verify your details.",
        "Congratulations! You are a winner of a free gift card.",
        "Hello, just checking in to confirm our meeting tomorrow."
    ]

    test_emails = [
        "user@gmail.com",
        "example@randomdomain.com",
        "noreply@sit.singaporetech.edu.sg",
        "fakeemail.com"
    ]

    print("===== Suspicious Keyword Tests =====")
    for txt in test_texts:
        print(find_suspicious_keywords(txt))

    print("\n===== Whitelist Tests =====")
    for email in test_emails:
        print(check_whitelist(email))