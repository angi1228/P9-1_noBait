from Levenshtein_homoglyphs import check_Levenshtein_homoglyphs

# List of safe email domains and sender names
from Constants import SAFE_SENDER_LIST
from Constants import SAFE_DOMAIN_LIST

def check_sender_and_display_name(display_name, sender_name, sender_domain):
    """
    Check if the sender's display name suggests a brand/org but the email domain does not match the official domain of that brand/org.
    """
    
    # If domain is in SAFE list, then the sender is safe
    if sender_domain in SAFE_DOMAIN_LIST:
        score, reason = 0, None
        return score, reason
    else:
        display_name = display_name.replace('"', '') # Remove any spaces and 
        # Check if sender_name or display_name contains any safe senders in the SAFE_SENDER_LIST, return true. Else, return None.
        check_suspicious = next(
                            (True for safe_sender in SAFE_SENDER_LIST if safe_sender in display_name or safe_sender in sender_name),
                            None
                            )
        
        suspicious_reason = None
        if check_suspicious != True:
            # normalised the display and sender name
            norm_display_name = display_name.replace(' ', '').replace('-', '').lower()
            norm_sender_name = sender_name.replace(' ', '').replace('-', '').lower()

            # Check for Levenshtein and homoglyphs
            while True:
                ## Check whether sender name and display name are similar to the safe senders and whether they contains any homoglyphs
                sender_name_result = check_Levenshtein_homoglyphs(norm_sender_name, SAFE_SENDER_LIST)
                display_name_result = check_Levenshtein_homoglyphs(norm_display_name, SAFE_SENDER_LIST)
                # Check the result of the output
                if sender_name_result['similar_string'] and display_name_result['similar_string']:
                    check_suspicious = True
                    suspicious_reason = (f'The sender\'s name and display name is similar to a legitimate domain')
                    break
                if sender_name_result['similar_string']:
                    check_suspicious = True
                    suspicious_reason = (f"The sender's name in their email address '{sender_name}' is similar to the official sender name '{sender_name_result['similar_string']}' but not the official domain")
                elif display_name_result['similar_string']:
                    check_suspicious = True
                    suspicious_reason = (f"The sender's display name '{display_name}' is similar to the safe sender '{display_name_result['similar_string']}' the official domain")
                break
            print(sender_name_result, display_name_result, suspicious_reason)

        # If True (the normalised sender or display name contains any of the safe senders in the SAFE_SENDER_LIST)
        if check_suspicious:
            if suspicious_reason == None:
                # suspcious as it's not in the safe domain but yet have the safe sender name
                suspicious_reason = "The email's display or sender name claims to be from the legitimate sender, but it is not"
            score, reason = 100, suspicious_reason             
        else: 
            score, reason = 0, suspicious_reason
        print(score, reason)
        return score, reason 


def check_domain(email_domain):
    '''
    To check whether the domain contains a homoglyphs that suggest a phishing attempt
    '''
    suspicious_result = check_Levenshtein_homoglyphs(email_domain, SAFE_DOMAIN_LIST)  

    if suspicious_result['suspicious']:
        suspicious_reason = "The sender's domain \"" + suspicious_result['input'] + "\" is similar to a legitimate domain \"" + suspicious_result['similar_string'] + "\""
    elif suspicious_result['suspicious'] == 'Unknown':
        suspicious_reason = "The sender's domain is unknown"
    else:
        suspicious_reason =''

    # Format to return back to the function
    score, reason = suspicious_result['risk_score'], suspicious_reason

    # NOTE Optional: pretty print
    print("\n--- Final Results Summary ---")
    print(score, reason)

    return score, reason # Return the score and reason (if any) 

if __name__ == "__main__":
    
    # Test cases
    # e.g., lets say the domain have already been extracted from the email
    email_domain_E1 = "gmai1l.com"  # Example email domain to check
    email_domain = email_domain_E2 = "micros0ft.com"  # Example email domain to check
    email_domain_E3 = "compaany.com"  # Example email domain to check
    email_domain_E4 = "yahoo.co"  # Example email domain to check
    email_domain_E5 = "g00ogle.co"  # Example email domain to check
    email_domain_E6 = "outlook.com"  # Example email domain to check

    # Levenshtein_homoglyphs_domains(email_domain)
    display_name_1 = 'g00ogle'
    display_name = display_name_2 = 'ITSupport Micr0soft'
    display_name_3 = 'Comppany'
    display_name_4 = 'YAh00'
    display_name_5 = 'Outlook'
    display_name_6 = 'ITsupp0rt'

    sender_name = 'test'

    sender_email_1 = 'amazonsupport@gmai1l.com'
    sender_email = sender_email_2 = 'support@m1soft.com'
    sender_email_3 = 'yahoosupport@yahoo.c0m'
    sender_email_4 = 'Google@g0ogle.com'
    sender_email_5 = 'Outlook-support@outlook.com'
    sender_email_6 = 'mycompany@comppany.com'
    check_sender_and_display_name(display_name, sender_name, email_domain)