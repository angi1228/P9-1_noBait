from email import policy
from email.parser import BytesParser
import re
import os

# directory that contains all email files to check
# directory = ""
# for file in os.scandir(directory):
#
# Parse email from a file
with open("0001.ea7e79d3153e7469e7a9c3e0af6a357e", "rb") as file:   # change filename as needed
    msg = BytesParser(policy=policy.default).parse(file)

WORD_CLEANER = re.compile(r'[^A-Za-z0-9 \n]+')

# Set of suspicious keywords to check for
suspicious_keywords = {'urgent', 'verify', 'account'}

# Function to extract the body from an EmailMessage object
def get_email_body():
    if msg.is_multipart():
        # Iterate over each part of a multipart message
        for part in msg.walk():
            # Check if the part is a text/plain or text/html part
            if part.get_content_type() in ("text/plain", "text/html"):
                return part.get_payload(decode=True).decode()
        return None
    else:
        # For non-multipart messages, simply return the payload
        return msg.get_payload(decode=True).decode()

body = get_email_body()

# Initialise dictionary to count suspicious words
early_count = {}
later_count = {}

def suspicious_subject():
    subject = msg['Subject']
    # removes special characters and whitespaces from the subject
    subject_cleaned = WORD_CLEANER.sub('', subject).lower()
    # split the words in the subject into elements of a list and ensure they are all in lowercase
    subject_words = subject_cleaned.split()
    for word in subject_words:
        if word in suspicious_keywords:
            early_count[word] = early_count.get(word, 0) + 1

suspicious_subject()


def suspicious_body():
    # removes special characters from the body
    body_cleaned = WORD_CLEANER.sub('', body).lower()
    # split the cleaned body into its respective lines
    body_lines = body_cleaned.splitlines()
    # take the first 10 lines of the body as priority
    priority_body = []
    for line in body_lines[:11]:
        priority_body.extend(line.split())
    # rest as secondary
    secondary_body = []
    for line in body_lines[11:]:
        secondary_body.extend(line.split())
    # count suspicious words in priority body
    for word in priority_body:
            if word in suspicious_keywords:
                early_count[word] = early_count.get(word, 0) + 1
    for word in secondary_body:
        if word in suspicious_keywords:
            later_count[word] = later_count.get(word, 0) + 1
    print(f"Priority words found: {early_count}")
    print(f"Secondary words found: {later_count}")
    return early_count, later_count

suspicious_body()

def assign_risk_score():
    risk_score = 0
    # sum the number of occurrences of suspicious words found in the subject + first 10 lines
    sum_count_early = sum(early_count.values())
    # sum the number of occurrences of suspicious words found in the rest of the body
    sum_count_later = sum(later_count.values())
    if sum_count_early == 0 and sum_count_later == 0:
        risk_score = 0
    elif sum_count_early == 0 and sum_count_later < 5:
        risk_score = 50.0
    elif sum_count_early == 0 and sum_count_later >= 5:
        risk_score = 65.0
    elif sum_count_early < 5:
        risk_score = 75.0
    elif sum_count_early >= 5:
        risk_score += 100.0

    print(f"Risk score from suspicious words found: {risk_score}")
    return risk_score

assign_risk_score()

