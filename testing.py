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
    reasons = []

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

    if count > 0:
        reasons.append("Suspicious keywords found")
    else:
        reasons.append("No suspicious keywords found")

    # Return array instead of dict
    return [risk_score, reasons, count, found]

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
    reasons = []

    # Extract domain
    domain = email.split("@")[1].lower()

    # Check if domain is in safe list
    if domain in [d.lower() for d in safe_domains]:
        is_safe = True
        reasons.append("Domain is in whitelist")
    else:
        risk_score += 100
        reasons.append("Domain is not in whitelist")

    # Return as array
    return [risk_score, is_safe, reasons, domain]

#Test Codesss
if __name__ == "__main__":
    # Test suspicious keyword detection
    test_email_text1 = "Urgent! Please verify your account immediately to avoid suspension."
    test_email_text2 = "Hello friend, just checking in. How are you doing?"

    print("Test 1 (suspicious):", find_suspicious_keywords(test_email_text1))
    print("Test 2 (not suspicious):", find_suspicious_keywords(test_email_text2))

    # Test whitelist check
    test_email1 = "user@gmail.com"
    test_email2 = "scammer@phishy.com"

    print("Whitelist Test 1 (safe):", check_whitelist(test_email1))
    print("Whitelist Test 2 (unsafe):", check_whitelist(test_email2))
