from Constants import SAFE_DOMAIN_LIST


def check_whitelist(email, domain):
    """
    Checks if sender's domain is part of trusted whitelist by 
    first validating the email address and domain then compare 
    against SAFE_DOMAIN_LIST to return risk score
    """

    risk_score = 0
    reason = ""

    # Validate the email format and domain value
    if "@" not in email or not domain or domain == "NA":
        risk_score = 100
        reason = "Invalid email format or missing domain"
        return risk_score, reason

    # Check if domain is in whitelist 
    normalized_domain = domain.lower().strip()
    whitelist = [d.lower() for d in SAFE_DOMAIN_LIST]

    if normalized_domain in whitelist:
        reason = ""
    else:
        risk_score = 100
        reason = f"Domain '{domain}' is not in whitelist"
    
    return risk_score, reason
