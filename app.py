from flask import Flask, render_template,request,jsonify,render_template_string
from email import message_from_string


app = Flask(__name__)
totalscore = 0

@app.route("/")
# def home():
#     return render_template("home.html")

def test():
    totalemails = ['email1','email2','email3','email4','malicious']
    totalscore = 0
    
    total_length = len(totalemails)
    
    suskeywords = ['pay','scam','malicious']

    for i in totalemails:
        if i in suskeywords:
            score = 9
            totalscore += score
            reason = f"{i} is very suspicous!!"

    return render_template("home.html",total_length=total_length,totalscore=totalscore,reason=reason)



def output():
    
    raw_email_content = """From: IT Support <it-support@example.com>
To: user@example.org
Subject: [TEST SIMULATION] Action Required — Verify Your Account
    Date: Tue, 9 Sep 2025 09:12:00 +0800
    Message-ID: <test1@example.com>

    THIS IS A PHISHING SIMULATION FOR TRAINING PURPOSES. DO NOT CLICK THE LINK BELOW.

    Dear user,

    We detected unusual activity on your account. To avoid suspension, please verify your account immediately:
    https://example.com/verify-account

    If you do not verify within 24 hours, your account will be suspended.

    Regards,
    IT Support
    """
    msg = message_from_string(raw_email_content)
    subject = msg['Subject']
    sender = msg['From']
    recipient = msg['To']
   
    body = None
    html_body = None

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            cdispo = part.get('Content-Disposition')

            # Extract plain text body
            if ctype == 'text/plain' and 'attachment' not in str(cdispo):
                body = part.get_payload(decode=True).decode()
                print(f"\nPlain Text Body:\n{body}")

            # Extract HTML body
            if ctype == 'text/html' and 'attachment' not in str(cdispo):
                html_body = part.get_payload(decode=True).decode()
                print(f"\nHTML Body:\n{html_body}")
            
            
    else:
        body = msg.get_payload(decode=True).decode()
        print(f"\nBody:\n{body}")
        
    return render_template("home.html",recipient = recipient,sender=sender,subject=subject,html_body=html_body,plain_body=body)

    

@app.route('/analyze', methods=['POST'])
def analyze_email():
    data = request.get_json()
    email_content = data.get('emailContent', '')
    print(email_content)

    # Return the results as JSON
    return jsonify({
        'success': True,
        'score': 6,   # e.g., 3.2
        'category': "Suspicous", # e.g., "Suspicious"
        'reasons': "calculated_reasons_list" # e.g., ["Reason 1", "Reason 2"]
    })









    
   


if __name__ in "__main__":
    app.run(debug=True)
    # test
