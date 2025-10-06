from Levenshtein import distance as levenshtein_distance
from typing import List

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


def check_Levenshtein_homoglyphs(input_string: str, SAFE_REFERENCE_LIST: List[str], threshold: int = 2): # Define a threshold for similarity in the last argument
    """
    Orchestrates the two-stage check for a single suspicious domain against a list of safe list.
    Stage 1: Fast Levenshtein Check (Standard Typos)
        Calculates the Levenshtein Distance of two strings this defines how many operations where needed to turn one string into another by inserting, removing or replacing a character
        input1 = "gooogle"
        input2 = "google"
        dist_calc = Levenshtein.distance(input1, input2)
        print(f"The Levenshtein distance between {input1} and {input2} is : {dist_calc}")
        ## Output: The Levenshtein distance between gooogle and google is : 2

    Stage 2: Intensive Homoglyph Check (Normalization + Levenshtein)
        Homoglyphs detection will perform a check for characters that look visually similar but have different unicode values. 
        It uses a predefined mapping of common homoglyph substitutions to flag suspicious email. 
        For example, if the domain address is “g00gle.com” when the legitimate domain is “google.com”, it will flag the domain as a suspicious domain when '0' are replaced with 'o'.
    """

    # Initialise return dictionary for when the domain is not suspicious
    result_safe = {
                'input': input_string,
                'suspicious': False,
                'risk_score': 0,
                'similar_string': None
                }

    safe_string = '' # Initliase safe_string to store the string from the SAFE_REFERENCE_LIST 

    # Dictionary for suspicious findings
    result_suspicious = {'input': input_string,
                        'suspicious': True,
                        'risk_score': 100,
                        'similar_string': safe_string
                        }
        
    # Dictionary for unknown domain (not in the list)
    result_unknown = {'input': input_string,
                        'suspicious': "Unknown",
                        'risk_score': 15,
                        'similar_string': None
                        }

    # Check if domain or sender is safe
    if input_string in SAFE_REFERENCE_LIST: 
        return result_safe
            
    # If not safe, continue checks

    # --- Stage 1: Fast Levenshtein Check (Standard Typos) ---
    for safe_string in SAFE_REFERENCE_LIST:
        # Get the Levenshtein_distance for each safe list compared to the input_string
        dist = levenshtein_distance(input_string, safe_string)
        if dist <= threshold:
            result_suspicious['similar_string'] = safe_string
            # Return suspicious if distance is within the threshold 
            return result_suspicious
        
         
    # --- Stage 2: Intensive Homoglyph Check (Normalization + Levenshtein) ---
    for safe_string in SAFE_REFERENCE_LIST:

        # Initialise variable
        normalised_string = None # To be used if input_string have been amended (means homoglyphs found and removed to a normal string) 

        for homoglyph, standard in COMMON_HOMOGLYPH_MAP.items():
            # If the homoglyph character is found in the input_string,
            if homoglyph in input_string:
                # replaces common homoglyphs with the standard string
                normalised_string = input_string.replace(homoglyph, standard)
        
        # If the original string was found to have homoglyphs,
        if normalised_string is not None: 
            
            # 'search' if any parts of the normalised string matches any string in the SAFE_REFERENCE_LIST
            if any(safe in normalised_string for safe in SAFE_REFERENCE_LIST):
                result_suspicious['similar_string'] = safe_string
                # Return suspicious is True (parts of the normalised string is found in SAFE_REFERENCE_LIST)
                return result_suspicious
                        
            # Run Levenshtein on the normalized strings
            dist_homoglyph = levenshtein_distance(normalised_string, safe_string)
            if dist_homoglyph <= threshold:
                result_suspicious['similar_string'] = safe_string
                # Return suspicious if found a close match (using Levenshtein distance) after homoglyph normalization 
                return result_suspicious
            
            # If the loop finishes without finding a close match of homoglyp
            return result_unknown
        
        # If there is no homoglyph characters in the input_string
        else:
            # Return unknown 
            return result_unknown
