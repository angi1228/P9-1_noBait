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
    riskscore = 0

    # list for riskscore 
    domain_score = []
    # for every url in list
    for i in parsed_url_list:
        if i.netloc not in TRUSTED_DOMAINS:     # if domain name not in trusted domains
            # print("UNTRUSTED")
            if i.netloc in SHORTENING_SERVICES: # if domain name is url shortener
                print("URL_SHORTENER USED")
                riskscore += 70
                print(riskscore)
                domain_score.append(riskscore)  
                break
            else:                                  # can't seem to get urls with unknown domains into else loop | check after restart
                print("UNTRUSTED DOMAIN")
                riskscore += 50
                print(riskscore)
                domain_score.append(riskscore)
                break
        else:
            print("Trusted")
            print(riskscore)
            domain_score.append(riskscore)
    print(domain_score)
    return domain_score

def check_page(parsed_url_list, domain_score):
    # run through url again
    count = 0 
    print(f'Score List: {domain_score}')
    for i in parsed_url_list:
        # if page name found in suspicious keywords
        print(i.path[1:])
        if i.path[1:] in SUSPICIOUS_KEYWORDS:       #  string sliced to remove /
            print("SUSPICIOUS PAGE NAME")
            print(domain_score[count])
            domain_score[count] += 50
            print(domain_score[count])
            break
        count+=1
    print(domain_score)
    return domain_score
        



def check_url(email_body):
    found_url_list = extract_URL(email_body)
    parsed_list = parse_URL(['http://yahoo.com', 'https://tinyurl.com/utdmmett', 'https://bankscam.net/login'])
    domainscore = check_domain(parsed_list)
    check_page(parsed_list, domainscore)
    #domain score is a list 
    parsed_list = parse_URL(found_url_list)
    domainscore = check_domain(parsed_list)
    check_page(parsed_list, domainscore)


check_url(body)