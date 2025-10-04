import Constants

# Initialise dictionary to count suspicious words
early_count = {}
later_count = {}


def suspicious_subject(subject):
    """
    this function counts the number of each suspicious keyword found in the subject of the email
    :param subject: subject of email to check
    :return: cleaned subject without special characters
    """
    # removes special characters and whitespaces from the subject
    subject_cleaned = Constants.WORD_CLEANER.sub('', subject)
    # split the words in the subject into elements of a list and ensure they are all in lowercase
    subject_words = subject_cleaned.lower().split()
    for word in subject_words:
        if word in Constants.SUSPICIOUS_KEYWORDS:
            early_count[word] = early_count.get(word, 0) + 1
    return subject_cleaned


def suspicious_body(email_body):
    """
    this function counts the number of each suspicious keyword found in the first 10 lines of the body of the email, and in the rest of the body
    :param email_body: body of the email to check
    :return: cleaned body without special characters
    """
    # removes special characters from the body
    body_cleaned = Constants.WORD_CLEANER.sub('', email_body)
    body_lower = body_cleaned.lower()
    # split the cleaned body into its respective lines
    body_lines = body_lower.splitlines()
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
    return body_cleaned


def count_capitals(clean_subject, clean_body):
    """
    this function counts the number of suspicious keywords that are fully capitalised in the subject and body
    :param clean_subject: cleaned subject of email
    :param clean_body: cleaned body of email
    :return: dictionary of the count of each capital keyword
    """
    capital_words = {}
    for word in clean_subject.split():
        if word.isupper() and word.lower() in Constants.SUSPICIOUS_KEYWORDS:
            capital_words[word] = capital_words.get(word, 0) + 1
    for word in clean_body.split():
        if word.isupper() and word.lower() in Constants.SUSPICIOUS_KEYWORDS:
            capital_words[word] = capital_words.get(word, 0) + 1
    return capital_words


def assign_risk_score(subject, body):
    """
    :param subject: subject of email to checK
    :param body: body of email to check
    :return: risk_score assigned to the email based on number and location of suspicious keywords found, reason for the risk_score assigned
    """
    clean_subject = suspicious_subject(subject)
    clean_body = suspicious_body(body)

    # sum the number of occurrences of suspicious words found in the subject + first 10 lines
    sum_count_early = sum(early_count.values())
    # sum the number of occurrences of suspicious words found in the rest of the body
    sum_count_later = sum(later_count.values())
    # sum the number of occurrences of capital letter words found in the email
    sum_count_capital = sum(count_capitals(clean_subject, clean_body).values())
    if sum_count_early >= 5:
        risk_score = 100.0
        verdict = "Highly Suspicious"
        reason = f"{sum_count_early} suspicious keywords found in subject or early in the body"
    elif sum_count_early > 0:
        risk_score = 75.0
        verdict = "Suspicious"
        reason = f"{sum_count_early} suspicious keywords found in subject or early in the body"
    elif sum_count_later >= 5:
        risk_score = 65.0
        verdict = "Suspicious"
        reason = f"{sum_count_later} suspicious keywords found in the body"
    elif sum_count_later > 0:
        risk_score = 50.0
        verdict = "Suspicious"
        reason = f"{sum_count_later} suspicious keywords found in the body"
    else:
        risk_score = 0.0
        verdict = "Safe"
        reason = "No suspicious keywords found"
    if sum_count_capital > 0:
        risk_score += sum_count_capital * 5  # tweak the multiplier (5) as needed
        reason += f",{sum_count_capital} suspicious keywords in capital letters"
        # cap at 100 so it doesn’t overflow
        if risk_score > 100:
            risk_score = 100
            verdict = "Highly Suspicious"
    return risk_score, reason

# subject = "WIN a FREE iPhone!!!"
# body = """
# Hello,
# This is your LAST chance to CLAIM your PRIZE.
# Click HERE NOW.
# """

# subject = Constants.extracted_data['Subject']
# body = Constants.extracted_data['Body']
# print(assign_risk_score(subject, body))

if __name__ == "__main__":
    print(assign_risk_score(subject, body))

