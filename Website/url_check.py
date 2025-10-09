import re
from urllib.parse import urlparse

from Constants import SUSPICIOUS_KEYWORDS
from Constants import SAFE_DOMAIN_LIST

SHORTENING_SERVICES = ['bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co', 'is.gd', 'bitly.com']

def extract_URL(email_body_text):
    '''Extract URLs from body string'''
    URL_REGEX = r'(?:http[s]?:\/\/.)?(?:www\.)?[-a-zA-Z0-9@%._\+~#=]{2,256}\.[a-z]{2,6}\b(?:[-a-zA-Z0-9@:%_\+.~#?&\/\/=]*)' 
    found_urls = re.findall(URL_REGEX, email_body_text)
    return found_urls

def parse_URL(url_list):
    '''splits URLS into different parts
            netloc = domain name eg outlook.com
            path = page name eg. /login
    '''
    parsed_list = []
    # loops through every url in url_list
    for i in url_list:                   # for every url in url_list
        
        parsed = urlparse(i)             # parse url
        
        parsed_list.append(parsed)       # append url to parsed_list
    
    return parsed_list

def check_domain(parsed_url_list):
    '''Checks riskscore of URL domain 
            trusted domain = 0
            Untrusted domain = 50
            URL shorteners = 70 
    '''
    # list for riskscore 
    domain_score = []
    
    for i in parsed_url_list:
        riskscore = 0
        
        if i.netloc not in SAFE_DOMAIN_LIST:     # if domain name not in trusted domains
            
            if i.netloc in SHORTENING_SERVICES: # if domain name is url shortener
                riskscore += 70
                domain_score.append(riskscore)  

            else:                                 
                riskscore += 50
                domain_score.append(riskscore)

        else:
            domain_score.append(riskscore)
    
    return domain_score

def check_page(parsed_url_list, domain_score):
    '''
    Checks risk score of URL page name
        Use suspicious keywords = 50
        No suspicious keywords = 0
    '''
    count = 0 
    
    for i in parsed_url_list:

        # if safe domain (domainscore =0)
        if domain_score[count] == 0:
            break
        
        # if path name in suspicious keywords
        if i.path[1:] in SUSPICIOUS_KEYWORDS or i.path[1:-1] in SUSPICIOUS_KEYWORDS:       #  string sliced to remove /
             
            # add 50 to score
            domain_score[count] += 50      
            break

        count+=1
    return domain_score
        

def generate_reason(domainscore, found_url_list):
    '''
    Appends risk assessment to riskscore
    Result is stored in dictionary format:
    {URL number : [riskscore, risk assessment]}
    '''
    reasonList = []
    # counter to find url
    counter = 0
    
    for i in domainscore:
        if i==0:
            reason = None
            reasonList.append(reason)

        elif i == 50:
            reason = f"URL is from an untrusted domain ({(found_url_list[counter])})"
            reasonList.append(reason)

        elif i == 70:
            reason = f"URL shortener used ({found_url_list[counter]})"
            reasonList.append(reason)

        elif i>=100:
            reason = f"Highly malicious: URL from untrusted domain and contain suspicious keyword ({found_url_list[counter]})"
            reasonList.append(reason)
        
        counter+=1

    # Dict Format {1: [riskscore,reason], 2:[riskscore,reason]....}
    # length = len(domainscore)          # length helps for defines number of loops to append to Dict

    # URL_Check_Dict = {}
    # for count in range(length):
    #     print(count, domainscore[count], reasonList[count])
        # generate dict of all urls checked
        # URL_Check_Dict[count] = [domainscore[count], reasonList[count]]
        
    # get index of highest score 
    result_index = domainscore.index(max(domainscore, default=0))
    
    # return url with highest score and its reason
    return domainscore[result_index], reasonList[result_index]


def check_url(found_url_list):
    '''Checks riskscore of URLs found in a body of text (str)'''

    if not found_url_list or found_url_list=='NA':
        return 0, ''
    
    parsed_list = parse_URL(found_url_list)
    
    domainscore = check_domain(parsed_list)
    
    Finaldomainscore = check_page(parsed_list, domainscore)
    
    max_score, score_reason = generate_reason(Finaldomainscore, found_url_list)

    url_reason = score_reason
    
    return int(max_score), url_reason 