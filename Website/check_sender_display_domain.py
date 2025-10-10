from Levenshtein_homoglyphs import check_Levenshtein_homoglyphs

# List of safe email domains and sender names
from Constants import SAFE_SENDER_LIST
from Constants import SAFE_DOMAIN_LIST

def check_sender_and_display_name(display_name, sender_name, sender_domain):
    """
    Checks for sender identity spoofing by comparing the sender's name and display name against a list of known safe senders/brands, 
    specifically when the email domain does not belong to the official safe list.

    The check is performed in two parts:
    1. Direct match: If the `sender_domain` is in `SAFE_DOMAIN_LIST`, the sender is immediately marked as safe.
    2. Fuzzy match: If the domain is *not* safe, it checks if the normalized sender name or display name is suspiciously similar to 
                    any known safe sender using Levenshtein distance and homoglyph checks (via `check_Levenshtein_homoglyphs`).

    :param display_name: The display name associated with the sender (e.g., 'Microsoft Support').
    :type display_name: str
    :param sender_name: The 'local part' of the sender's email address (e.g., 'security').
    :type sender_name: str
    :param sender_domain: The domain of the sender's email address (e.g., 'micr0soft.com').
    :type sender_domain: str
    :raises: No explicit exceptions, but relies on proper functioning of 'check_Levenshtein_homoglyphs'.
    :return: A tuple containing the risk score (0 or 100) and the reason string.
    :rtype: tuple[int, str]

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
            suspicious_reason = (f'Deceptive sender name "{sender_name}" or display name "{display_name}", non-matching domain')

        # Return the risk_score and reason for being suspicious (if any)
        if is_suspicious:
            score, reason = 100, suspicious_reason             
        else: 
            score, reason = 0, suspicious_reason

        return score, reason 


def check_domain(email_domain):
    '''
    Analyzes the provided email domain for similarity to known safe domains, specifically checking for typosquatting (Levenshtein distance) and homoglyph attacks.

    This function relies entirely on the two-stage process defined in `check_Levenshtein_homoglyphs` against the `SAFE_DOMAIN_LIST`.

    :param email_domain: The domain part of the email address (e.g., 'apple.c0m').
    :type email_domain: str
    :return: A tuple containing the risk score (e.g., 0, 15, or 100) and the reason for the classification (e.g., "The sender's domain is similar to...").
    :rtype: tuple[int, str]
    '''

    # Get a dictionary of the result from the function
    suspicious_result = check_Levenshtein_homoglyphs(email_domain, SAFE_DOMAIN_LIST)  

    # Check whether the result returns whether the sender's domain is suspicious
    if suspicious_result['suspicious'] == 'Unknown':
        suspicious_reason = ""
    elif suspicious_result['suspicious']:
        suspicious_reason = "The sender's domain \"" + suspicious_result['input'] + "\" is similar to a legitimate domain \"" + suspicious_result['similar_string'] + "\""
    else:
        suspicious_reason = ''

    # Format to return back to the function
    score, reason = suspicious_result['risk_score'], suspicious_reason

    return score, reason # Return the score and reason (if any) 
