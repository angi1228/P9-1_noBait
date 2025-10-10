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
    Orchestrates a two-stage check for a single input string (domain or sender name) against a list of safe reference strings to detect typosquatting and homoglyph attacks.
    
    The function first performs a fast Levenshtein check for similarity between the input string and the SAFE_REFERENCE_LIST, if no similarity is found, it then performs 
    an intensive check involving character normalization (homoglyph detection and replacement) followed by a second Levenshtein/substring check.

    :param input_string: The string to be checked (e.g., 'micr0soft' or 'microsfot.com').
    :type input_string: str
    :param SAFE_REFERENCE_LIST: A list of known safe strings (domains or sender names).
    :type SAFE_REFERENCE_LIST: list[str]
    :param threshold: The maximum allowed Levenshtein distance to be considered a suspicious match. Defaults to 2.
    :type threshold: int
    :return: A dictionary containing the analysis results:
             - 'input': The original input string.
             - 'suspicious': Boolean or "Unknown". True if suspicious, False if safe, "Unknown" if not in the list and no similarity found.
             - 'risk_score': The score associated with the finding (0, 15, or 100).
             - 'similar_string': The specific string from the SAFE_REFERENCE_LIST that caused the match, or None.
    :rtype: dict
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
                        'risk_score': 25,
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
    
        # Initialise variable
    normalised_string = None # To be used if input_string have been amended (means homoglyphs found and removed to a normal string) 

    for homoglyph, standard in COMMON_HOMOGLYPH_MAP.items():
        # If the homoglyph character is found in the input_string,
        if homoglyph in input_string:
            # replaces common homoglyphs with the standard string
            normalised_string = input_string.replace(homoglyph, standard)
         
    # --- Stage 2: Intensive Homoglyph Check (Normalization + Levenshtein) ---        
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
