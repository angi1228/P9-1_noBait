from Levenshtein_homoglyphs import check_Levenshtein_homoglyphs

# List of safe email domains and sender names
from Constants import SAFE_SENDER_LIST
from Constants import SAFE_DOMAIN_LIST

def check_sender_and_display_name(display_name, sender_name, sender_domain):
    """
    Check if the sender and display name suggests a brand or organisation but the email domain does not match the official domain of that brand or organisation. 
    Note that Gmail and Office/Hotmail is not considered as a whitelisted email domain due to common use by the public.
    """
    
    # If domain is safe list, then the sender is safe
    if sender_domain in SAFE_DOMAIN_LIST:
        score, reason = 0, "" # return risk score of 0 and no reason as it is not suspicious
        return score, reason
    
    # If domain is not in the safe list, continue checking the sender and display name
    else: 
        # Normalised the display name
        norm_display_name = display_name.replace(' ', '').replace('-', '').lower() # Remove any spaces and dashes
        
        # Check if sender_name or display_name contains any safe senders in the SAFE_SENDER_LIST
        # If sender_name or display_name is in the safe senders list, return True (sucpicious). Else, return False (not suspicious).
        is_suspicious = next(
                            (True for safe_sender in SAFE_SENDER_LIST if safe_sender in norm_display_name or safe_sender in sender_name),
                            False
                            )
        
        suspicious_reason = "" # Holds the reason for the analysis being suspicious
        # If the sender_name or display_name is not in the safe senders list, then do further checking to ensure it's indeed not suspicious
        if is_suspicious is False: 
            # Normalised the sender name
            norm_sender_name = sender_name.replace(' ', '').replace('-', '').lower() # Remove any spaces and dashes

            while True:
                ## Check whether sender name and display name are similar to the safe senders (Levenshtein distance) and whether they contains any homoglyphs
                sender_name_result = check_Levenshtein_homoglyphs(norm_sender_name, SAFE_SENDER_LIST)
                display_name_result = check_Levenshtein_homoglyphs(norm_display_name, SAFE_SENDER_LIST)

                # Check the result of the above variables to determine whether the sender name and display name is suspicious and return the reason (if suspicious)
                if sender_name_result['suspicious'] == 'Unknown' and display_name_result['suspicious'] == "Unknown":
                    suspicious_reason = "" # Not suspicious 
                    break
                elif sender_name_result['suspicious'] and display_name_result['suspicious']: # if both is True
                    suspicious_reason = (f'The sender\'s name "{sender_name}" and display name "{display_name}" is similar to a legitimate domain')
                    is_suspicious = True
                    break
                elif sender_name_result['suspicious']:
                    suspicious_reason = (f"The sender's name in their email address '{sender_name}' is similar to the official sender name '{sender_name_result['similar_string']}' but not the official domain")
                    is_suspicious = True
                    break
                elif display_name_result['suspicious']:
                    suspicious_reason = (f"The sender's display name '{display_name}' is similar to the safe sender '{display_name_result['similar_string']}' the official domain")
                    is_suspicious = True
                    break
                else: 
                    suspicious_reason = "" # Not suspicious 
                break

        else: # If sender_name or display_name is in the safe senders list without needing to check for Levenshtein distance and homoglyphs
            suspicious_reason = 'Deceptive sender name or display name, non-matching domain'

        # Return the risk_score and reason for being suspicious (if any)
        if is_suspicious:
            score, reason = 100, suspicious_reason             
        else: 
            score, reason = 0, suspicious_reason

        return score, reason 


def check_domain(email_domain):
    '''
    To check whether the domain is similar to the safe domain list by checking for any homoglyphs and similarity to the safe domains (using Levenshtein distance) that suggest a phishing attempt. 
    '''

    # Get a dictionary of the result from the function
    suspicious_result = check_Levenshtein_homoglyphs(email_domain, SAFE_DOMAIN_LIST)  

    # Check whether the result returns whether the sender's domain is suspicious
    if suspicious_result['suspicious'] == 'Unknown':
        suspicious_reason = "The sender's domain is unknown"
    elif suspicious_result['suspicious']:
        suspicious_reason = "The sender's domain \"" + suspicious_result['input'] + "\" is similar to a legitimate domain \"" + suspicious_result['similar_string'] + "\""
    else:
        suspicious_reason = ''

    # Format to return back to the function
    score, reason = suspicious_result['risk_score'], suspicious_reason

    return score, reason # Return the score and reason (if any) 
