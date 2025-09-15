import re
from urllib.parse import urlparse

body = "Click Below For Accessories On All NOKIA, MOTOROLA LG, NEXTEL, SAMSUNG, QUALCOMM, ERICSSON, AUDIOVOX PHONES At Below WHOLESALE PRICES! http://www.chinaniconline.com/sales/"

SUSPICIOUS_KEYWORDS = ['login', 'verify', 'update', 'banking', 'secure', 'account', 'password', 'sales', 'action','download', 'win', 'prize' ]

SHORTENING_SERVICES = ['bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co', 'is.gd']

TRUSTED_DOMAINS = ['gmail.com', 'outlook.com', 'neo.email', 'yahoo.com',
                   'proton.me', 'protonmail.com', 'icloud.com', 'zohomail.com',
                   'aol.com', 'tuta.com', 'tutanota.com', 'mailfence.com',
                   'sit.singaporetech.edu.sg']

# Extract URL from body text
def extract_URL(email_body_text):
    # URL_REGEX = r'(https:\/\/www\.|http:\/\/www\.|https:\/\/|http:\/\/)?[a-zA-Z0-9]{2,}(\.[a-zA-Z0-9]{2,})(\.[a-zA-Z0-9]{2,})?\/[a-zA-Z0-9]{2,}'
    URL_REGEX = r'(?:http[s]?:\/\/.)?(?:www\.)?[-a-zA-Z0-9@%._\+~#=]{2,256}\.[a-z]{2,6}\b(?:[-a-zA-Z0-9@:%_\+.~#?&\/\/=]*)'
    found_urls = re.findall(URL_REGEX, email_body_text)
    print(found_urls)
    # output as list
    return found_urls

# Parse URL
def parse_URL(url_list):
    parsed_list = []
    # loops through every url in url_list
    for i in url_list:                   # for every url in url_list
        parsed = urlparse(i)             # parse url
        print(parsed)
        # print(parsed.scheme)
        # print(parsed.netloc)
        parsed_list.append(parsed)       # append url to parsed_list
    return parsed_list

# domain check
def check_domain(parsed_url_list):
    for i in parsed_url_list:
        if i.netloc not in TRUSTED_DOMAINS:
            print("UNTRUSTED")
            break
        print("Trusted")






found_url_list = extract_URL(body)
parsed_list = parse_URL(['http://yahoo.com'])
check_domain(parsed_list)
parsed_list = parse_URL(found_url_list)
check_domain(parsed_list)
