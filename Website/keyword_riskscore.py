import Constants


def suspicious_subject(subject):
    """
    this function counts the number of each suspicious keyword found in the subject of the email
    :param subject: subject of email to check
    :return: cleaned subject without special characters
    """
    early_count = {}
    # removes special characters and whitespaces from the subject
    subject_cleaned = Constants.WORD_CLEANER.sub('', subject)
    # split the words in the subject into elements of a list and ensure they are all in lowercase
    subject_lower = subject_cleaned.lower()
    for word in Constants.SUSPICIOUS_KEYWORDS:
        count = subject_lower.count(word)
        if count > 0:
            early_count[word] = early_count.get(word, 0) + count
    return subject_cleaned, early_count


def suspicious_body(email_body, early_count):
    """
    this function counts the number of each suspicious keyword found in the first 10 lines of the body of the email, and in the rest of the body
    :param email_body: body of the email to check
    :param early_count: dictionary of keyword counts in subject and early in the body
    :return: cleaned body without special characters
    """
    later_count = {}
    # removes HTML tags, encoded characters and special chars from the body
    body_cleaned = Constants.TAG_CLEANER.sub('', email_body)
    body_cleaned = Constants.ENCODED_CLEANER.sub('', body_cleaned)
    body_cleaned = Constants.WORD_CLEANER.sub('', body_cleaned)
    body_lower = body_cleaned.lower()
    # split the cleaned body into its respective lines
    body_lines = body_lower.splitlines()
    # take the first 10 lines of the body as priority
    # join priority lines and secondary lines into strings
    priority_text = "\n".join(body_lines[:11])
    secondary_text = "\n".join(body_lines[11:])
    # count suspicious words in priority body
    for word in Constants.SUSPICIOUS_KEYWORDS:
        count_priority = priority_text.count(word)
        if count_priority > 0:
            early_count[word] = early_count.get(word, 0) + count_priority
        count_secondary = secondary_text.count(word)
        if count_secondary > 0:
            later_count[word] = later_count.get(word, 0) + count_secondary
    return body_cleaned, early_count, later_count


# def count_capitals(clean_subject, clean_body):
#     """
#     this function counts the number of suspicious keywords that are fully capitalised in the subject and body
#     :param clean_subject: cleaned subject of email
#     :param clean_body: cleaned body of email
#     :return: dictionary of the count of each capital keyword
#     """
#     capital_words = {}
#     combined = clean_subject + "\n" + clean_body
#     combined_upper = combined.upper()
#     # check for uppercase suspicious keywords in the email
#     for word in Constants.SUSPICIOUS_KEYWORDS:
#         word_upper = word.upper()
#         count = combined_upper.count(word_upper)
#         if count > 0:
#             capital_words[word] = capital_words.get(word, 0) + count
#     return capital_words


def assign_risk_score(subject, body):
    """
    :param subject: subject of email to check
    :param body: body of email to check
    :return: risk_score assigned to the email based on number and location of suspicious keywords found, reason for the risk_score assigned
    """
    clean_subject, early_count = suspicious_subject(subject)
    clean_body, early_count, later_count = suspicious_body(body, early_count)

    # sum the number of occurrences of suspicious words found in the subject + first 10 lines
    sum_count_early = sum(early_count.values())
    # sum the number of occurrences of suspicious words found in the rest of the body
    sum_count_later = sum(later_count.values())
    # sum the number of occurrences of capital letter words found in the email
    sum_count_capital = sum(count_capitals(clean_subject, clean_body).values())
    # assign a risk score and reason based on where the bulk of suspicious keywords are found
    if sum_count_early >= 5:
        risk_score = 100.0
        reason = f"Early Keyword Analysis: {sum_count_early} suspicious keywords found in subject or early in the body"
    elif sum_count_early > 0:
        risk_score = 75.0
        reason = f"Early Keyword Analysis: {sum_count_early} suspicious keywords found in subject or early in the body"
    elif sum_count_later >= 5:
        risk_score = 65.0
        reason = f"Body Keyword Analysis: {sum_count_later} suspicious keywords found in the body"
    elif sum_count_later > 0:
        risk_score = 50.0
        reason = f"Body Keyword Analysis: {sum_count_later} suspicious keywords found in the body"
    else:
        risk_score = 0.0
        reason = ""
    if sum_count_capital > 0:
        risk_score += sum_count_capital * 5
        reason += f", Capitalised Keyword Emphasis: {sum_count_capital} suspicious keywords in capital letters"
        # cap at 100 so it does not overflow
        risk_score = min(risk_score, 100)
    return risk_score, reason




