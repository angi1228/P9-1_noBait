from email import message_from_string

raw_email_content = """From: IT Support <it-support@example.com>
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
msg = message_from_string(raw_email_content)



subject = msg['Subject']
sender = msg['From']
recipient = msg['To']
print(f"Subject: {subject}")
print(f"From: {sender}")
print(f"To: {recipient}")




if msg.is_multipart():
    for part in msg.walk():
        ctype = part.get_content_type()
        cdispo = part.get('Content-Disposition')

        # Extract plain text body
        if ctype == 'text/plain' and 'attachment' not in str(cdispo):
            body = part.get_payload(decode=True).decode()
            print(f"\nPlain Text Body:\n{body}")

        # Extract HTML body
        if ctype == 'text/html' and 'attachment' not in str(cdispo):
            html_body = part.get_payload(decode=True).decode()
            print(f"\nHTML Body:\n{html_body}")
else:
    body = msg.get_payload(decode=True).decode()
    print(f"\nBody:\n{body}")