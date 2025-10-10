from flask import Flask, render_template, request
import zipfile, io
from datetime import datetime

# Import different functions that check for phishing signs in the email
from Constants import extract_email_parts
from check_sender_display_domain import check_domain
from check_sender_display_domain import check_sender_and_display_name
from url_check import check_url
from keywords_check import find_suspicious_keywords
from whitelist_check import check_whitelist
from financedetect import check_financial_request
from keyword_riskscore import assign_risk_score

# Create a Flask app
app = Flask(__name__, template_folder='.')

c_cmf_phishing = 0 # Count the number of confirmed phishing emails. Inital value: 0
c_suspicious_email=0 # Count the number of suspicious emails. Inital value: 0
c_safe_emails=0 # Count the number of safe emails. Initial value: 0
c_emails_analyse=0 # Count the number of emails scanned. Initial value: 0

# ----------------------------
# Home Page
# ----------------------------
@app.route("/")
def home():
    # When you open the main page, show index.html
    # Some sample values (phishing, anothernumber, etc.) are sent to template
    return render_template(
        "index.html",
        phishing=c_cmf_phishing,
        anothernumber=c_safe_emails,
        sum=c_emails_analyse,
        sus=c_suspicious_email
    )

# ----------------------------
# Analyze raw email content (text)
# ----------------------------
@app.route('/analyze', methods=['POST'])
def analyze_email():
    global c_cmf_phishing    # Declared global to modify
    global c_suspicious_email   # Declared global to modify
    global c_safe_emails        # Declared global to modify
    global c_emails_analyse     # Declared global to modify
    
    # Reset values to 0 (When user upload multiple times)
    c_cmf_phishing = 0 
    c_suspicious_email=0 
    c_safe_emails=0 
    c_emails_analyse=0

    # Get email text from the form
    email_content = request.form.get('emailContent', '')
    if not email_content.strip():
        # If nothing was entered, show error
        return render_template("index.html", error="No email content provided")

    # Run the analyzer function on the email content
    result = analyze_email_content_detailed(email_content)

    # Pass results back to the template to display 
    return render_template("index.html",
                            score=result.get('score', 0),                  # Matches {{ score }}
                            category=result.get('category', 'Error'),      # Matches {{ category }}
                            reasons=result.get('reasons', []),             # Matches {{ reasons }}
                            email_content=email_content,                   # Matches {{ email_content }} 
                            # ... (Global Counters) ...
                            phishing=c_cmf_phishing,
                            anothernumber=c_safe_emails,
                            sum=c_emails_analyse,
                            sus=c_suspicious_email
                        )

# ----------------------------
# Analyze uploaded file (single email file or zip file)
# ----------------------------
@app.route('/analyze-file', methods=['POST'])
def analyze_file():
    global c_cmf_phishing    # Declared global to modify
    global c_suspicious_email   # Declared global to modify
    global c_safe_emails        # Declared global to modify
    global c_emails_analyse     # Declared global to modify

    # Reset values to 0 (When user upload multiple times)
    c_cmf_phishing = 0 
    c_suspicious_email=0 
    c_safe_emails=0 
    c_emails_analyse=0

    # Check if a file was uploaded
    if 'file' not in request.files:
        return render_template("index.html", error="No file uploaded")

    file = request.files['file']
    if file.filename == '':
        return render_template("index.html", error="No file selected")

    try:
        # If uploaded file is a zip file
        if file.filename.lower().endswith('.zip'):
            results = []
            # Open the zip file in memory (without saving to disk)
            with zipfile.ZipFile(io.BytesIO(file.read())) as z:
                # Loop through each file inside the zip
                for name in z.namelist():
                    if name.endswith("/"):
                        continue
                    # Only process email-like files and non attachment
                    if name.lower().endswith(('.eml', '.txt', '.html', '')):
                        try:
                            # Read the content of the file inside zip
                            content = z.read(name).decode('utf-8', errors='ignore')
                            # Run the analyzer
                            result = analyze_email_content_detailed(content)
                            # Save result along with filename
                            results.append({**result, "filename": name, "email_content": content})
                        except Exception as e:
                            # If one file fails, still continue and log error
                            results.append({'filename': name, 'error': str(e)})

        # Pass results back to the template to display 
            return render_template(
                "index.html",
                zip_results=results, # For parsing of zip files
                # ... (Global Counters) ...
                phishing=c_cmf_phishing,
                anothernumber=c_safe_emails,
                sum=c_emails_analyse,
                sus=c_suspicious_email
            )


        else:
            # If uploaded file is just a single email file (not zip)
            content = file.read().decode('utf-8', errors='ignore')
            result = analyze_email_content_detailed(content)

            return render_template("index.html",
                                   filename=file.filename,                         # Pass filename for display
                                    score=result.get('score', 0),                  # Matches {{ score }}
                                    category=result.get('category', 'Error'),      # Matches {{ category }}
                                    reasons=result.get('reasons', []),             # Matches {{ reasons }},
                                    email_content=content,
                                    # ... (Global Counters) ...
                                    phishing=c_cmf_phishing,
                                    anothernumber=c_safe_emails,
                                    sum=c_emails_analyse,
                                    sus=c_suspicious_email,
                                   )

    except Exception as e:
        # If something goes wrong, show error
        return render_template("index.html", error=f"Error processing file: {str(e)}")

# ----------------------------
# Main Analyzer - combines all checks
# ----------------------------

def analyze_email_content_detailed(content: str):
    """
    Run all the analysis functions.
    Update the global variables.
    Calculate the final result and parse it to the webpage.
    """
    global c_cmf_phishing    # Declared global to modify
    global c_suspicious_email   # Declared global to modify
    global c_safe_emails        # Declared global to modify
    global c_emails_analyse     # Declared global to modify

    # 1. Get Constants before running the analysis
    email_parts = extract_email_parts(content) # Returns the email parts 

    # Set Initial values
    combined_analysis = {"f_risk_score":0, "combined_reasons":[]} # To store key-pairs in a dictionary to parse to the webpage
    f_risk_score = 0    # Store the total risk score from all analysis
    f_risk_score = 0    # Store the final risk score after calculating overall risk

    # Retrieve email parts from the Constants.py
    email_subject = email_parts.get('subject', 'N/A')
    email_body = email_parts.get('body', 'N/A')
    email_sender_name = email_parts.get('sender_name','NA')
    email_domain_name = email_parts.get('sender_domain','NA')
    email_address = email_parts.get('email_address', "NA")
    
    print(f"============\n!!Email Subject: {email_subject} \n\n ============\n!!Email Body: {email_body} \n\n !============\n!Email address: {email_address} \n\n \
          ============\n!!Email sender name: {email_sender_name} \n\n ============\n!!Display name: {email_parts.get('display_name', 'N/A')} \n\n \
            ============\n!!Email domain name: {email_domain_name} \n\n ============\n!!URLs: {email_parts.get('urls', 'NA')}")
    
    # Function 4: Check the Sender Name/Display Name for spoofing
    score_func_4, reason = check_sender_and_display_name(display_name=email_parts.get('display_name', 'N/A'), 
                                                sender_name=email_sender_name, 
                                                sender_domain=email_domain_name)
    combined_analysis['combined_reasons'].append(reason)
    print(f"!!!Function 4 - Score: ({score_func_4}), Reason: ({reason})")
   
    # Function 5: Check Domain Name for spoofing     
    score_func_5, reason = check_domain(email_domain_name)
    combined_analysis['combined_reasons'].append(reason)
    print(f"!!!Function 5 - Score: ({score_func_5}), Reason: ({reason})")

    # If spoofing is found in the email header, display name, or the domain name, it is 100% a phishing email
    if score_func_4 == 100 or score_func_5 == 100:
        f_risk_score += 100
        
    else: # Continue checking
        # Function 1: Suspicious Keyword checks on subject and body
        subject_and_body = email_subject + '\n' + email_body
        ## Get suspicious keywords
        score, reason = find_suspicious_keywords(subject_and_body)
        f_risk_score += score*0.0 # Ignore the risk score
        combined_analysis['combined_reasons'].append(reason)
        print(f"============\n!!!Function 1.1 (1st: Get list of sus keyword) - Score: ({score*0.0}), Reason: ({reason})")
        ## Assign risk score
        score, reason = assign_risk_score(email_subject, email_body)
        f_risk_score += score*0.40
        combined_analysis['combined_reasons'].append(reason)
        print(f"!!!Function 1.2 (2nd: Get risk score) - Score: ({score*0.40}), Reason: ({reason})")

        # Function 2: Verify whether domain is valid and in the whitelist
        score, reason = check_whitelist(email_address, email_domain_name)
        f_risk_score += score*0.20
        combined_analysis['combined_reasons'].append(reason)

        print(f"!!!Function 2 - Score: ({score*0.20}), Reason: ({reason})")
        
        # Function 3: Check URL
        score, reason = check_url(found_url_list=email_parts.get('urls', 'NA'))
        f_risk_score += score*0.20
        combined_analysis['combined_reasons'].append(reason)

        print(f"!!!Function 3 - Score: ({score*0.20}), Reason: ({reason})")    

        # Function 6: Detect for any financial request
        score, reason = check_financial_request(email_body)
        f_risk_score += score*0.20
        combined_analysis['combined_reasons'].append(reason)

        print(f"!!!Function 6 - Score: ({score*0.20}), Reason: ({reason})")


    combined_analysis['f_risk_score'] = f_risk_score

    print(f"!!!Finial Risk Score (add up): {f_risk_score}")

    # Map the risk score to a conclusion and risk level. 
    if f_risk_score >= 70:
        c_cmf_phishing += 1 # Add count to the number of confimred phsihing emails
        conclusion = "Phishing"
    elif f_risk_score >= 50:
        c_suspicious_email += 1 # Consider as suspicious email
        conclusion = "Moderately Suspicious"
    elif f_risk_score >= 40:
        c_suspicious_email += 1 # Consider as suspicious email
        conclusion = "Low Suspicious"
    else:
        c_safe_emails += 1 # Consider as safe email
        conclusion = "Safe"
        
    # Successfully scanned 1 email
    c_emails_analyse += 1 
    
    # Add conclusion to the dictionary for parsing to webpage
    combined_analysis['conclusion'] = conclusion

    print(f"=============\n!!!Conclusion/Category: {conclusion}\nTotal Reasons: {combined_analysis['combined_reasons']}")

    # Return to parse to the webpage
    return {
        "score": round(f_risk_score, 1),
        "category": conclusion,
        "reasons": combined_analysis['combined_reasons'],
    }

# ----------------------------
# Run the app
# ----------------------------
if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
    