import re
from urllib.parse import urlparse

def check_links(content: str):
    score, reasons = 0.0, []
    domain_reputation = "Good"
    suspicious_domains = []

    links = re.findall(r'http[s]?://[^\s<>"]+', content)
    for link in links:
        domain = urlparse(link).netloc
        if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
            score += 2; suspicious_domains.append(domain); domain_reputation = "Poor"; continue
        shorteners = ["bit.ly","goo.gl","tinyurl.com","t.co","ow.ly","is.gd","buff.ly","click.me"]
        if any(s in domain for s in shorteners):
            score += 1; suspicious_domains.append(domain)
            if domain_reputation != "Poor": domain_reputation = "Suspicious"

    if suspicious_domains:
        reasons.append(f"Suspicious domains found: {', '.join(suspicious_domains[:3])}")
    return score, reasons, domain_reputation