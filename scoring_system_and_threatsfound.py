import re
from email import message_from_string
from collections import defaultdict
from urllib.parse import urlparse

# Define a dictionary of scoring rules
SCORING_RULES = {
    # Sender Reputation
    'suspicious_domain_age': 20, # Placeholder for logic checking domain age
    'mismatched_sender_headers': 25,
    
    # URL Analysis
    'link_text_mismatch': 15,
    'obfuscated_url': 20,
    
    # Content Analysis
    'urgent_keywords': 10,
    'credential_requests': 40,
    'spelling_errors': 5,
}

# Define lists of keywords for content analysis
URGENT_KEYWORDS = ['urgent', 'immediately', 'action required', 'act now']
CREDENTIAL_REQUESTS = ['password', 'username', 'verify your account', 'click here to login']
COMMON_SPELLING_ERRORS = ['acount', 'verfiy', 'immediatley'] # A very small example

def calculate_threat_score(email_content):
    """Calculates a threat score for a given email content."""
    score = 0
    email_message = message_from_string(email_content)
    
    # 1. Header Analysis
    from_header = email_message.get('From', '')
    return_path = email_message.get('Return-Path', '')
    if '@' in from_header and '@' in return_path:
        from_domain = from_header.split('@')[-1]
        return_domain = return_path.split('@')[-1]
        if from_domain.lower() != return_domain.lower():
            score += SCORING_RULES['mismatched_sender_headers']
            print("Threat found: Mismatched sender headers")

    # 2. Body Content Analysis
    email_body = email_message.get_payload(decode=True).decode(errors='ignore')
    email_body_lower = email_body.lower()

    # Look for urgent keywords
    if any(keyword in email_body_lower for keyword in URGENT_KEYWORDS):
        score += SCORING_RULES['urgent_keywords']
        print("Threat found: Urgent keywords")

    # Look for credential requests
    if any(keyword in email_body_lower for keyword in CREDENTIAL_REQUESTS):
        score += SCORING_RULES['credential_requests']
        print("Threat found: Credential requests")

    # Look for common spelling errors
    if any(error in email_body_lower for error in COMMON_SPELLING_ERRORS):
        score += SCORING_RULES['spelling_errors']
        print("Threat found: Spelling errors")

    # 3. URL Analysis (this is a simplified example)
    # Find all URLs in the email body
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*(),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', email_body)
    
    # Find all anchor text and check for mismatch
    links_with_text = re.findall(r'<a.*?href="(.*?)".*?>(.*?)</a>', email_body, re.IGNORECASE)
    for url, text in links_with_text:
        # Check if the domain in the link text matches the actual URL domain
        if urlparse(url).netloc not in text:
            score += SCORING_RULES['link_text_mismatch']
            print(f"Threat found: Link text mismatch. URL: {url}, Text: {text}")

    # A more advanced system would use VirusTotal or other APIs to check the URLs reputation.
    
    return score

# Example Usage
if __name__ == "__main__":
    
    # Example of a low-threat email
    safe_email = """From: Alice <alice@safe-company.com>
To: Bob <bob@example.com>
Subject: Weekly Report

Hi Bob,

Here is the weekly report you asked for.

Thanks,
Alice
"""
    
    # Example of a high-threat (phishing) email
    phishing_email = """From: Security Alert <security@secure-update.com>
To: Bob <bob@example.com>
Subject: Urgent: Your account has been compromised

Your acount has been accessed from a new location. We need to verify your account immediately.
Please log in by clicking this link: <a href="http://malicious-login.com/login">secure-company.com/login</a>

Failure to act now will result in your account being suspended.

Thanks,
Secure Team
"""
    
    safe_score = calculate_threat_score(safe_email)
    print(f"\nSafe Email Score: {safe_score}")
    
    phishing_score = calculate_threat_score(phishing_email)
    print(f"\nPhishing Email Score: {phishing_score}")

    # Interpret the score
    def interpret_score(score):
        Final_Risk_Score = {"Safe":50,'Suspicious':65,'Moderate Suspicious':80,'Highly Suspicious':100}
        for category,threshhold in Final_Risk_Score.items():

            if score <= threshhold:
                print(f"Final Score: {score}\tCategory: {category}")
                return

    # print(f"\nSafe Email Interpretation: {interpret_score(safe_score)}")
    # print(f"Phishing Email Interpretation: {interpret_score(phishing_score)}")
