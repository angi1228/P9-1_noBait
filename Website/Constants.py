import re
from email import policy
from email.parser import Parser
from email.utils import parseaddr

# common constants

EMAIL_BODY = []

# For whitelist, sender domain check, url check
SAFE_DOMAIN_LIST = ['google.com','microsoft.com','amazon.com','mycompany.com','sit.singaporetech.edu.sg', 'singaporetech.edu.sg', 
                    'xsite.singaporetech.edu.sg', 'newsletter.online.com', 'cnet.com', 'www.cnet.com', 'home.cnet.com', 
                    'zdnet.com', 'www.theregister.co.uk', 'clickthru.online.com', 'docs.yahoo.com', 'us.click.yahoo.com', 
                    'www.pcworld.com', 'forms.google.com', 'www.openssl.org', 'www.nme.org', 'www.unesco.org', 'www.oreilly.com', 
                    'grabfood.com', 'nlb.gov.sg', 'experience.nlb.gov.sg']

# for sender domain check
SAFE_SENDER_LIST = ['google','microsoft','yahoo','clickthruonline','newsletteronline','theregister','pcworld','openssl',
                    'amazonsupport','homecnet','singaporetech','mycompany', 'list.theregister.co.uk', 'grabfood', 'golibrarybynlb']


# For keyword check, url check
SUSPICIOUS_KEYWORDS = [
        "urgent", "limited time", "account", "terminated", "suspended", "compromised", "on hold",
        "violation", "verify", "last warning", "final notice", "final call", "last call", "last chance",
        "important notice", "login", "password", "locked", "pay", "overdue", "action",  "required",
        "transfer", "claim your refund", "download", "winner", "free", "gift", "prize",
        "congratulations", "you have been selected", "claim your reward", "exclusive", "special offer",
        "no cost", "guaranteed", "dear customer", "favour", "sexy", "sex", "sexual", "hot", "single", "near you", "meet singles",
        "dating", "babes", "babe", "nude", "naked", "gambling", "horny", "money", "cash", "payment", "payments", "credit card", "credit cards", "loan",
        "offer", "deal", "sales", "earn", "membership", "bank", "fees", "visa", "mastercard", "insurance", "rates", "income", "fortune", "fortunes", "invoice",
        "file", "request", "verification", "VM", "call"
    ]

# 1. Remove HTML tags like <p>, <b>, </a>, etc.
TAG_CLEANER = re.compile(r'<[^>]+>')

# 2. Remove encoded characters like =3D or <=
ENCODED_CLEANER = re.compile(r'=[A-Za-z0-9]+|=<')

# 3. Remove special characters
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

    # 1.4 Extract email sender name
    email_parts['sender_name'] = email_address.split("@")[0].lower()
    
    # 1.5 Extract email domain name
    email_parts['sender_domain'] = email_address.split("@")[-1].lower()
    
    # 1.6 Extract Email Title
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
    url_pattern_ip_addr = r'http[s]?:\/\/[-a-zA-Z0-9@%._\+~#=]{2,256}\.[a-z]{2,6}\b[-a-zA-Z0-9@:%_\+.~#?&\/\/=]*'
    url_pattern_domain_addr = r'http[s]?:\/\/[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.\b[-a-zA-Z0-9@:%_\+.~#?&\/\/=]*'
    email_parts['urls'] = list(set(re.findall(url_pattern_ip_addr, body)))
    email_parts['urls'] += list(set(re.findall(url_pattern_domain_addr, body)))

    return email_parts


