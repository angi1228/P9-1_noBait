


url_riskscore = 0
linkshorten = ["1apple.com"]
not_trusted_domain = ["malicious.site"]
url_link_to_check = ["malicious.site"]
suspiciouskeywords = ['login','verify','update']

for i in url_link_to_check:

    if i in linkshorten:
        

        url_riskscore = 70

    elif i in not_trusted_domain:
        print(i)
        url_riskscore = 50
        if url_link_to_check in suspiciouskeywords:
            url_riskscore += 50

if url_riskscore < 50:
    print("is not suspicous")
elif url_riskscore < 70:
    print("reason: from an untrusted domain!")
elif url_riskscore <100:
    print("URL shortened used!")
else:
    print("Highly Malcious: URL FROM untrusted domain and contain suspicious keywords!")

print(f"url score: "+ str(url_riskscore))
def scoringsystem(score):
    Final_Risk_Score = {"Safe":50,'Suspicious':65,'Moderate Suspicious':80,'Highly Suspicious':100}

  
    for category,threshhold in Final_Risk_Score.items():

        if score <= threshhold:
            print(f"Final Score: {score}\tCategory: {category}")
            break
       
       

scoringsystem(81)

