r'''
1. Levenshtein.distance
    Calculates the Levenshtein Distance of two strings this defines how many operations where needed to turn one string into another by inserting, removing or replacing a character
        input1 = "gooogle"
        input2 = "google"
        dist_calc = Levenshtein.distance(input1, input2)
        print(f"The Levenshtein distance between {input1} and {input2} is : {dist_calc}")
        The Levenshtein distance between gooogle and google is : 2
    Will need further checks if used -> e.g., Cooking and Looking is   similar but doesn't mean its a phishing email

2. Homoglyphs detection will perform a check for characters that look visually similar but have different unicode values. 
    It uses a predefined mapping of common homoglyph substitutions to flag suspicious email. 
    For example, if the domain address is “g00gle.com” when the legitimate domain is “google.com”, it will flag the domain as a suspicious domain when '0' are replaced with 'o'.
'''

from Levenshtein import distance as levenshtein_distance
import homoglyphs as hg
from typing import List


''' --- Data Setup --- '''

# List of safe email domains
SAFE_DOMAIN_LIST = ['google.com','microsoft.com','neo.email','yahoo.com','proton.me','protonmail.com','icloud.com','mycompany.com',
                    'aol.com','tuta.com','tutanota.com','mailfence.com','sit.singaporetech.edu.sg', 'singaporetech.edu.sg','company.com']
SAFE_SENDER_LIST = ['google','microsoft','neo','yahoo','proton','icloud','zoho','aol', 'tuta','tutanota','mailfence',
                    'sit','company','itsupport']

# Predefined mapping of common homoglyph
COMMON_HOMOGLYPH_MAP  = {
    '0': 'o',      # Digit zero for letter 'o' (e.g., g00gle.com)
    '1': 'l',      # Digit one for letter 'l' (e.g., app1e.com)
    '3': 'e',      # Digit three for letter 'e'
    '4': 'a',      # Digit four for letter 'a'
    '5': 's',      # Digit five for letter 's'
    '2': 'z',      # Digit two for letter 'z'
    '@': 'a',      # At-sign for letter 'a'
    '|': 'i',      # Pipe for letter 'i' (covers l and I visually)
    '!': 'i',      # Exclamation mark for letter 'i'
    
    # Common Cyrillic/Unicode characters
    'А': 'A',      # Uppercase Cyrillic A
    'а': 'a',      # Cyrillic 'a'
    'е': 'e',      # Cyrillic 'e'
    'о': 'o',      # Cyrillic 'o'
    'р': 'p',      # Cyrillic 'er'
    'с': 'c',      # Cyrillic 'es'
    'у': 'y',      # Cyrillic 'u'
    'і': 'i',      # Latin 'i' with dotless
}


''' --- Core Logic Functions --- '''

# Function to check if an email domain is safe

def check_display_name_vs_domain():
    """
    Check if the sender's display name suggests a brand/org but the email domain does not match the official domain of that brand/org.
    """
    suspicious_result = []
    
    # normalised display name
    display_name_list = [display_name_1,display_name_2,display_name_3, display_name_4,display_name_5,display_name_6]

    # normalise sender name and domain name from email address
    sender_email_list = [sender_email_1, sender_email_2, sender_email_3, sender_email_4, sender_email_5, sender_email_6]

    # Check if display name or sender name contains any known brand keyword in the SAFE_SENDER_LIST
    for display_name, sender_email in zip(display_name_list, sender_email_list):
        normalised_sender_name = sender_email.split("@")[0].lower()
        normmalised_sender_domain = sender_email.split("@")[-1].lower()
        normalised_display_name = display_name.lower()

        result_safe = {
            "sender_name": sender_email,
            "sender_email": sender_email,
            "suspicious": False,
            'risk_score': 0,
            "reason": None
        }
        result_suspicious = {
            "sender_name": sender_email,
            "sender_email": sender_email,
            "suspicious": True,
            'risk_score': 80,
            "reason": 'Display or sender name is similar to a legitimate domain'
        }
        
        # If domain is in SAFE list, then the sender is safe
        if normmalised_sender_domain in SAFE_DOMAIN_LIST:
            suspicious_result.append(result_safe)
            continue
        else:
            # Check if normalised_sender_name or normalised_display_name contains any safe senders in the SAFE_SENDER_LIST
            check_name_to_safe_list = next(
                                    (safe_sender for safe_sender in SAFE_SENDER_LIST if safe_sender in normmalised_sender_domain or safe_sender in normalised_sender_name),
                                    None
                                    )
            # If True (the normalised sender or display name contains any of the safe senders in the SAFE_SENDER_LIST)
            if check_name_to_safe_list:
                print(f"Display name suggests IN THE SAME SENDER LIST but domain is not the official_domains")
                suspicious_result.append(result_suspicious) # suspcious as it's not in the safe domain but yet have the safe sender name
            else: # Sender name is not the same as the value name
                suspicious_result.append(result_safe)
                    
    # Optional: pretty print
    print("\n--- Final Results Summary (Sender Names) ---")
    print(suspicious_result)
    for res in suspicious_result:
        print(f"{res['sender_name']}: {res['sender_email']}, {res['suspicious']}, {res['risk_score']} {res['reason']}\n")
    return suspicious_result

def Levenshtein_homoglyphs_domains():
    '''
    To check whether the domain contains a homoglyphs that suggest a phishing attempt
    '''
    suspicious_result = []
    #NOTE: TO CHANGE THE VARIABLE NAME BECAUSE OF  DOMAIN NAME
    for email_domain in [email_domain_E1, email_domain_E2, email_domain_E3, email_domain_E4, email_domain_E5, email_domain_E6]:
        email_domain = email_domain.split('@')[-1] # To get the domain, though in this case no need
        suspicious_result.append(check_Levenshtein_homoglyphs(email_domain, SAFE_DOMAIN_LIST))
    
    # Optional: pretty print
    print("\n--- Final Results Summary ---")
    print(suspicious_result)
    for res in suspicious_result:
        print(f"{res['input']}: {res['suspicious']}, {res['risk_score']} {res['similar_domain']}\n")

    return suspicious_result # Give back the suspicious result to user

def check_Levenshtein_homoglyphs(input_item: str, SAFE_REFERENCE_LIST: List[str], threshold: int = 2):
    """
    Orchestrates the two-stage check for a single suspicious domain against a list of safe domains or senders.
    """
    result_safe = {
        'input': input_item,
        'suspicious': False,
        'risk_score': 0,
        'similar_domain': None
    }

    # normalised to lowercase
    input_item = input_item.lower()

    if input_item in SAFE_REFERENCE_LIST: # Check if domain or sender is safe
        return result_safe
            
    # If not safe, continue checks
    
    threshold = 2  # Define a threshold for similarity

    # --- Stage 1: Fast Levenshtein Check (Standard Typos) ---
    for safe_domain in SAFE_REFERENCE_LIST:
        dist = levenshtein_distance(input_item, safe_domain)
        print(f"1. Levenshtein distance between '{input_item}' and '{safe_domain}': {dist}")
        if dist <= threshold:
            # Consider suspicious if distance is within the threshold
            print(f"2. Domain '{input_item}' is flagged as suspicious due to similarity with '{safe_domain}'.")
            return  {'input': input_item,
                    'suspicious': True,
                    'risk_score': 100,
                    'similar_domain': safe_domain
                    }
         
    # --- Stage 2: Intensive Homoglyph Check (Normalization + Levenshtein) ---
    for safe_domain in SAFE_REFERENCE_LIST:
        result_suspicious = {'input': input_item,
                            'suspicious': True,
                            'risk_score': 100,
                            'similar_domain': safe_domain
                            }
        result_unknown = {'input': input_item,
                        'suspicious': "Unknown",
                        'risk_score': 20,
                        'similar_domain': None
                        }
        normalised_domain = None
        # Replaces common homoglyphs to original domain
        input_item = input_item.replace('-','') # Cleanup 
        for homoglyph, standard in COMMON_HOMOGLYPH_MAP.items():
            if homoglyph in input_item:
                normalised_domain = input_item.replace(homoglyph, standard)
        
        if normalised_domain != None:
            if any(safe in normalised_domain for safe in SAFE_REFERENCE_LIST):
                print(f"4. Suspicious Domain Detected: {normalised_domain} is similar to {safe_domain} (Homoglyph detected)")
                safe_domain = safe_domain
                return result_suspicious
            # else:
            #     # If the loop finishes without finding a close match of homoglyph or result
            #     print(f"5. [{input_item}] ✅ Not suspicious after homohlyph.")
            
            # Run Levenshtein on the normalized strings
            distance_homoglyph = levenshtein_distance(normalised_domain, safe_domain)

            if distance_homoglyph <= threshold:
                # Found a close match after homoglyph normalization 
                print(f"6. [{input_item, normalised_domain}] 🚨 Flagged (Homoglyph Check, Dist={distance_homoglyph}) vs {safe_domain}")
                safe_domain = safe_domain
                return result_suspicious
            # else:
            #     # If the loop finishes without finding a close match of homoglyph
            #     print(f"7. [{input_item, normalised_domain}] ✅ Not suspicious against known list.")
            return result_unknown
        else:
            return result_unknown
                    

# def check_display_name_vs_domain(sender_name: str, sender_email: str, SAFE_DOMAIN_LIST: List[str]) -> dict:
#     """
#     Check if the sender's display name suggests a brand/org but the email domain does not match the official domain of that brand/org.
#     """
#     result_safe = {
#         "sender_name": sender_name,
#         "sender_email": sender_email,
#         "suspicious": False,
#         'risk_score': None,
#         "reason": None
#     }

#     # Normalize input
#     sender_name = sender_name.lower()
#     domain = sender_email.split("@")[-1].lower() # Get the domain name

#     # If domain is in SAFE list, then okay, the sender is safe
#     if domain in SAFE_DOMAIN_LIST:
#         return result_safe

#     # Check if sender_name contains any known brand keyword
#     for safe_sender in SAFE_SENDER_LIST:
#         if safe_sender in sender_name:
#             # But the domain is not one of the brand’s official domains
#             official_domains = [d for d in SAFE_DOMAIN_LIST if safe_sender in d]
#             if not any(official_domain in domain for official_domain in official_domains):
#                 result_safe["suspicious"] = True
#                 result_safe["reason"] = f"Display name suggests '{safe_sender}' but domain is {domain}, not {official_domains}"
#                 return result_safe

#     return result_safe




# Check if the email domain is safe
if __name__ == "__main__":
    
    # Test cases
    # e.g., lets say the domain have already been extracted from the email
    email_domain_E1 = "gmai1l.com"  # Example email domain to check
    email_domain_E2 = "micros0ft.com"  # Example email domain to check
    email_domain_E3 = "compaany.com"  # Example email domain to check
    email_domain_E4 = "yahoo.co"  # Example email domain to check
    email_domain_E5 = "g00ogle.co"  # Example email domain to check
    email_domain_E6 = "outlook.com"  # Example email domain to check

    # Levenshtein_homoglyphs_domains()
    display_name_1 = 'g00ogle'
    display_name_2 = 'micros0ft'
    display_name_3 = 'Comppany'
    display_name_4 = 'YAh00'
    display_name_5 = 'Outlook'
    display_name_6 = 'ITsupp0rt'

    sender_email_1 = 'amazonsupport@gmai1l.com'
    sender_email_2 = 'support@m1soft.com'
    sender_email_3 = 'yahoosupport@yahoo.c0m'
    sender_email_4 = 'Google@g0ogle.com'
    sender_email_5 = 'Outlook-support@outlook.com'
    sender_email_6 = 'mycompany@comppany.com'
    check_display_name_vs_domain()

