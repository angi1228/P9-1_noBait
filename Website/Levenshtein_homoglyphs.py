r'''
1. Levenshtein.distance
    Calculates the Levenshtein Distance of two strings this defines how many operations where needed to turn one string into another by inserting, removing or replacing a character
        input1 = "gooogle"
        input2 = "google"
        dist_calc = Levenshtein.distance(input1, input2)
        print(f"The Levenshtein distance between {input1} and {input2} is : {dist_calc}")
        ## Output: The Levenshtein distance between gooogle and google is : 2

2. Homoglyphs detection will perform a check for characters that look visually similar but have different unicode values. 
    It uses a predefined mapping of common homoglyph substitutions to flag suspicious email. 
    For example, if the domain address is “g00gle.com” when the legitimate domain is “google.com”, it will flag the domain as a suspicious domain when '0' are replaced with 'o'.
'''

from Levenshtein import distance as levenshtein_distance
from typing import List

# --- Data Setup --- 

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


def check_Levenshtein_homoglyphs(input_item: str, SAFE_REFERENCE_LIST: List[str], threshold: int = 2):
    """
    Orchestrates the two-stage check for a single suspicious domain against a list of safe list.
    """
    result_safe = {
        'input': input_item,
        'suspicious': False,
        'risk_score': 0,
        'similar_string': None
    }

    if input_item in SAFE_REFERENCE_LIST: # Check if domain or sender is safe
        return result_safe
            
    # If not safe, continue checks
    
    threshold = 2  # Define a threshold for similarity

    # --- Stage 1: Fast Levenshtein Check (Standard Typos) ---
    for safe_string in SAFE_REFERENCE_LIST:
        dist = levenshtein_distance(input_item, safe_string)
        # print(f"1. Levenshtein distance between '{input_item}' and '{safe_string}': {dist}")
        if dist <= threshold:
            # Consider suspicious if distance is within the threshold
            # print(f"2. Domain '{input_item}' is flagged as suspicious due to similarity with '{safe_string}'.")
            return  {'input': input_item,
                    'suspicious': True,
                    'risk_score': 100,
                    'similar_string': safe_string
                    }
         
    # --- Stage 2: Intensive Homoglyph Check (Normalization + Levenshtein) ---
    for safe_string in SAFE_REFERENCE_LIST:
        # Dictionary for suspiocious findings
        result_suspicious = {'input': input_item,
                            'suspicious': True,
                            'risk_score': 100,
                            'similar_string': safe_string
                            }
        #  Dictionary for unknown findings
        result_unknown = {'input': input_item,
                        'suspicious': "Unknown",
                        'risk_score': 15,
                        'similar_string': None
                        }
        
        # Replaces common homoglyphs 
        normalised_string = None
        for homoglyph, standard in COMMON_HOMOGLYPH_MAP.items():
            if homoglyph in input_item:
                normalised_string = input_item.replace(homoglyph, standard)
        
        if normalised_string != None: # If the original string was found to have homoglyphs
            # 'Search' or find if the cleaned string matches any string in the SAFE_REFERENCE_LIST
            if any(safe in normalised_string for safe in SAFE_REFERENCE_LIST):
                # print(f"4. Suspicious Domain Detected: {normalised_string} is similar to {safe_string} (Homoglyph detected)")
                return result_suspicious
            # else:
            #     # If the loop finishes without finding a close match of homoglyph or result
            #     print(f"5. [{input_item}] ✅ Not suspicious after homohlyph.")
            
            # Run Levenshtein on the normalized strings
            distance_homoglyph = levenshtein_distance(normalised_string, safe_string)
            if distance_homoglyph <= threshold:
                # Found a close match after homoglyph normalization 
                print(f"6. [{input_item, normalised_string}] 🚨 Flagged (Homoglyph Check, Dist={distance_homoglyph}) vs {safe_string}")
                return result_suspicious
            # else:
            #     # If the loop finishes without finding a close match of homoglyph
            #     print(f"7. [{input_item, normalised_string}] ✅ Not suspicious against known list.")
            return result_unknown
        else:
            return result_unknown

# if __name__ == "__main__":
    
#     # Test cases
#     # e.g., lets say the domain have already been extracted from the email
#     email_domain_E1 = "gmai1l.com"  # Example email domain to check
#     email_domain = email_domain_E2 = "micros0ft.com"  # Example email domain to check
#     email_domain_E3 = "compaany.com"  # Example email domain to check
#     email_domain_E4 = "yahoo.co"  # Example email domain to check
#     email_domain_E5 = "g00ogle.co"  # Example email domain to check
#     email_domain_E6 = "outlook.com"  # Example email domain to check

#     # Levenshtein_homoglyphs_domains(email_domain)
#     display_name_1 = 'g00ogle'
#     display_name = display_name_2 = 'ITSupport Micr0soft'
#     display_name_3 = 'Comppany'
#     display_name_4 = 'YAh00'
#     display_name_5 = 'Outlook'
#     display_name_6 = 'ITsupp0rt'

#     sender_name = 'test'

#     sender_email_1 = 'amazonsupport@gmai1l.com'
#     sender_email = sender_email_2 = 'support@m1soft.com'
#     sender_email_3 = 'yahoosupport@yahoo.c0m'
#     sender_email_4 = 'Google@g0ogle.com'
#     sender_email_5 = 'Outlook-support@outlook.com'
#     sender_email_6 = 'mycompany@comppany.com'
#     check_Levenshtein_homoglyphs(display_name, sender_name, email_domain)

