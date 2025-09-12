import email
# from email.parser import BytesParser

# Bytes object containing the raw email content
# example email
raw_email_bytes = b"From: test@email.com\r\nSubject: Test Email Subject, verify Now\r\n\r\nThis is the email body."

contents = email.message_from_bytes(raw_email_bytes)
subject = contents['Subject']
header_keys = contents.keys()
header_values = contents.values()
print(f"Header values: {header_values}")

detected_keywords = ['urgent', 'verify', 'account']

for i in detected_keywords:
    if i in subject:
        print(f"{i} has a risk score of 2.0")
