# common constants 

EMAIL_BODY = []

# For whitelist, sender domain check, url check
SAFE_DOMAIN_LIST = ['google.com','microsoft.com','neo.email','yahoo.com','proton.me','protonmail.com','icloud.com','mycompany.com',
                    'aol.com','tuta.com','tutanota.com','mailfence.com','sit.singaporetech.edu.sg', 'singaporetech.edu.sg']


# for sender domain check
SAFE_SENDER_LIST = ['google','microsoft','neo','yahoo','proton','icloud','zoho','aol', 'tuta','tutanota','mailfence', 'sit','mycompany','itsupport']


# For keyword check, url check
SUSPICIOUS_KEYWORDS = [
        "urgent", "immediately", "limited time", "account", "terminated", "suspended", "compromised", "on hold",
        "violation", "verify", "last warning", "final notice", "final call", "last call", "last chance",
        "important notice", "login", "password", "security", "locked", "pay", "overdue", "action required",
        "transfer", "claim your refund", "download", "click", "won", "winner", "free", "gift", "prize",
        "congratulations", "you have been selected", "claim your reward", "exclusive", "special offer",
        "no cost", "guaranteed", "dear customer", "favour", "sexy", "hot", "single", "near you", "meet singles",
        "dating", "babes", "babe", "nude", "naked", "money", "cash", "payment", "payments", "credit card", "loan",
        "offer", "deal", "sales", "earn", "membership"
    ]

'''
I: Parsing email, extracting body, email, safe sender list, cleaning email
'''