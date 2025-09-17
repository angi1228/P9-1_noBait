import email
import re
from email import policy
from email.parser import BytesParser

def extract_email_parts(eml_file_path):
    """Parses an .eml file to extract headers, body, and URLs."""
    
    with open(eml_file_path, 'rb') as fp:
        msg = BytesParser(policy=policy.default).parse(fp)
    
    email_parts = {}
    
    # 1. Extract headers
    email_parts['headers'] = dict(msg.items())
    
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
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    email_parts['urls'] = re.findall(url_pattern, body)
    
    return email_parts

# --- Example Usage ---
# First, create a dummy email file for this example.
dummy_email_content = """From: IT Support <it-support@example.com>
To: user@example.org
Subject: [TEST SIMULATION] Action Required — Verify Your Account
Date: Tue, 9 Sep 2025 09:12:00 +0800
Message-ID: <test1@example.com>

THIS IS A PHISHING SIMULATION FOR TRAINING PURPOSES. DO NOT CLICK THE LINK BELOW.

Dear user,

We detected unusual activity on your account. To avoid suspension, please verify your account immediately:
https://example.com/verify-account

If you do not verify within 24 hours, your account will be suspended.

Regards,
IT Support


"""

# with open('test_email.eml', 'w') as f:
#     f.write(dummy_email_content)

# Now, extract the parts from the dummy file
extracted_data = extract_email_parts('test_email.eml')

print("--- Headers ---")
for key, value in extracted_data['headers'].items():
    print(f"{key}: {value}")

print("\n--- Body ---")
print(extracted_data['body'].strip())

print("\n--- URLs ---")
for url in extracted_data['urls']:
    print(url)