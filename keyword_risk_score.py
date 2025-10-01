import Constants

# Initialise dictionary to count suspicious words
early_count = {}
later_count = {}

def suspicious_subject():
    subject = Constants.extracted_data['headers']['Subject']
    # removes special characters and whitespaces from the subject
    subject_cleaned = Constants.WORD_CLEANER.sub('', subject).lower()
    # split the words in the subject into elements of a list and ensure they are all in lowercase
    subject_words = subject_cleaned.split()
    for word in subject_words:
        if word in Constants.SUSPICIOUS_KEYWORDS:
            early_count[word] = early_count.get(word, 0) + 1

suspicious_subject()


def suspicious_body():
    # removes special characters from the body
    body_cleaned = Constants.WORD_CLEANER.sub('', Constants.extracted_data['body']).lower()
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
            if word in Constants.SUSPICIOUS_KEYWORDS:
                early_count[word] = early_count.get(word, 0) + 1
    for word in secondary_body:
        if word in Constants.SUSPICIOUS_KEYWORDS:
            later_count[word] = later_count.get(word, 0) + 1
    return early_count, later_count



def assign_risk_score():
    # sum the number of occurrences of suspicious words found in the subject + first 10 lines
    sum_count_early = sum(early_count.values())
    # sum the number of occurrences of suspicious words found in the rest of the body
    sum_count_later = sum(later_count.values())
    if sum_count_early >= 5:
        return {"risk_score" : 100.0, "verdict": "Highly Suspicious", "reason": f"{sum_count_early} suspicious keywords found in subject or early in the body"}
    if sum_count_early > 0:
        return {"risk_score": 75.0, "verdict": "Suspicious",
                "reason": f"{sum_count_early} suspicious keywords found in subject or early in the body"}
    if sum_count_later >= 5:
        return {"risk_score": 65.0, "verdict": "Suspicious", "reason": f"{sum_count_later} suspicious keywords found in the body"}
    if sum_count_later > 0:
        return {"risk_score": 50.0, "verdict": "Suspicious", "reason": f"{sum_count_later} suspicious keywords found in the body"}
    return {"risk_score" : 0.0, "verdict": "Safe", "reason": "No suspicious keywords found"}

print(assign_risk_score())

