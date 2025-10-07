import re
from email import policy
from email.parser import Parser
from email.utils import parseaddr

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
        "offer", "deal", "sales", "earn", "membership", "bank", "details"
    ]

#regex to remove special characters from email
WORD_CLEANER = re.compile(r'[^A-Za-z0-9 \n]+')


def extract_email_parts(file_content):
    """Parses a file to extract headers, body, and URLs."""

    # with open(eml_file_path, 'rb') as fp:
    parser = Parser()
    msg = parser.parsestr(file_content)

    email_parts = {}

    # 1. Extract headers
    email_parts['headers'] = dict(msg.items())

    # 1.0 Extract Display Name and Email Address
    sender_header = msg.get('From', '')
    display_name, email_address = parseaddr(sender_header)
    
    # 1.2 Extract Display Name
    email_parts['display_name'] = display_name or "NA"
    
    # 1.3 Extract Email Address
    email_parts['email_address'] = email_address or "NA"

    """ 
    Add sender_name and sender_domain for app.py compatibility
    sender_name: full email address (used in spoofing/whitelist check)
    sender_domain: domain part of email address (used in whitelist check)
    """
    email_parts['sender_name'] = email_address or "NA"
    if "@" in email_address:
        email_parts['sender_domain'] = email_address.split("@")[-1].lower()
    else:
        email_parts['sender_domain'] = "NA"
    
    
    # 1.4 Extract Email Title
    email_parts['subject'] = msg.get('Subject', '').strip() 

    # 2. Extract body
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            # If the part is plain text, decode and add it
            if part.get_content_type() == 'text/plain':
                body += part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='ignore')
                break  # Stop after finding the first plain text part
    else:
        # For non-multipart messages, get the body directly
        body = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8', errors='ignore')
    email_parts['body'] = body

    # 3. Extract URLs from the body using regex
    url_pattern = r'(?:http[s]?:\/\/.)?(?:www\.)?[-a-zA-Z0-9@%._\+~#=]{2,256}\.[a-z]{2,6}\b(?:[-a-zA-Z0-9@:%_\+.~#?&\/\/=]*)'
    email_parts['urls'] = re.findall(url_pattern, body)

    return email_parts


if __name__ == '__main__':
    file_content = """\
From: sender@exampe.xom
To: example@gmail.com
Subject: TEst


THis is the body of the tmeial

"""
    extracted_data = extract_email_parts(file_content)
    print("--- Headers ---")
    for key, value in extracted_data['headers'].items():
        print(f"{key}: {value}")

    print("\n--- Body ---")
    print(extracted_data['body'].strip())

    print("\n--- URLs ---")
    for url in extracted_data['urls']:
        print(url)

    # Print the Display Name
    display_name = extracted_data.get('display_name', 'N/A')
    print(f"Display Name: {display_name}")

    # Print the Email Address
    email_address = extracted_data.get('email_address', 'N/A')
    print(f"Email Address: {email_address}")
