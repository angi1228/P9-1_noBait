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

# NOTE: TEMPORARY PLACEMENT - TO MOVE
c_cmf_phsihing = 0 # Count the number of confirmed phishing emails. Inital value: 0
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
        phishing=c_cmf_phsihing,
        safe_email_scanned=c_safe_emails,
        email_to_anaylse=c_emails_analyse,
        suspicious_email_scanned=c_suspicious_email
    )
#testing
# ----------------------------
# Analyze raw email content (text)
# ----------------------------
@app.route('/analyze', methods=['POST'])
def analyze_email():
    # Get email text from the form
    email_content = request.form.get('emailContent', '')
    if not email_content.strip():
        # If nothing was entered, show error
        return render_template("index.html", error="No email content provided")

    # Run the analyzer function on the email content
    result = analyze_email_content_detailed(email_content)

    # Pass results back to the template to display ## NOTE: YX To link from here
    return render_template("index.html",
                            score=result.get('score', 0),                  # Matches {{ score }}
                            category=result.get('category', 'Error'),      # Matches {{ category }}
                            reasons=result.get('reasons', []),             # Matches {{ reasons }}
                            email_content=email_content,                   # Matches {{ email_content }} (and acts as display trigger)
                            # ... (Global Counters) ...
                            phishing=c_cmf_phsihing,
                            safe_email_scanned=c_safe_emails,
                             email_to_anaylse=c_emails_analyse,
                            suspicious_email_scanned=c_suspicious_email
                        )

# ----------------------------
# Analyze uploaded file (single email file or zip file)
# ----------------------------
@app.route('/analyze-file', methods=['POST'])
def analyze_file():
    
    # Check if a file was uploaded
    if 'file' not in request.files:
        return render_template("index.html", error="No file uploaded")

    file = request.files['file']
    print("DEBUG -- filename:", file.filename)
    if file.filename == '':
        print('122222')
        return render_template("index.html", error="No file selected")

    try:
        # If uploaded file is a zip file
        if file.filename.lower().endswith('.zip'):
            results = []
            # Open the zip file in memory (without saving to disk)
            with zipfile.ZipFile(io.BytesIO(file.read())) as z:
                # Loop through each file inside the zip
                for name in z.namelist():
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
            # Show results for all files inside the zip
            # return render_template("index.html", zip_results=results,
            #                        phishing=c_cmf_phsihing, anothernumber=c_safe_emails,
            #                        sum=c_emails_analyse, sus=c_suspicious_email)
                # Pass results back to the template to display ## NOTE: YX To link from here
            return render_template(
                "index.html",
                zip_results=results,
                score=result.get('score', 0),                  # Matches {{ score }}
                category=result.get('category', 'Error'),      # Matches {{ category }}
                reasons=result.get('reasons', []),             # Matches {{ reasons }}
                email_content=content,                   # Matches {{ email_content }} (and acts as display trigger)
                # ... (Global Counters) ...
                phishing=c_cmf_phsihing,
                safe_email_scanned=c_safe_emails,
                 email_to_anaylse=c_emails_analyse,
                suspicious_email_scanned=c_suspicious_email
            )


        else:
            print("334343")
            # If uploaded file is just a single email file (not zip)
            content = file.read().decode('utf-8', errors='ignore')
            print("DEBUG -- content length:", len(content))
            result = analyze_email_content_detailed(content)
            print("DEBUG -- result:", result)
            print("DEBUG -- content length:", len(content))

            return render_template("index.html",
                                   filename=file.filename, # Pass filename for display
                                    score=result.get('score', 0),                  # Matches {{ score }}
                                    category=result.get('category', 'Error'),      # Matches {{ category }}
                                    reasons=result.get('reasons', []),             # Matches {{ reasons }},
                                    email_content=content,
                                    # ... (Global Counters) ...
                                    phishing=c_cmf_phsihing,
                                    safe_email_scanned=c_safe_emails,
                                     email_to_anaylse=c_emails_analyse,
                                    suspicious_email_scanned=c_suspicious_email,
                                   )

    except Exception as e:
        # If something goes wrong, show error
        return render_template("index.html", error=f"Error processing file: {str(e)}")

# ----------------------------
# Main Analyzer - combines all checks
# ----------------------------

def analyze_email_content_detailed(content: str):
    global c_cmf_phsihing # MUST be declared global to be modified
    global c_suspicious_email # MUST be declared global to be modified
    global c_safe_emails # MUST be declared global to be modified
    global c_emails_analyse # MUST be declared global to be modified

    # 1. Get Constants before running the analysis
    email_parts = extract_email_parts(content) # Returns the email parts 
    print("DEBUG -- content length:", len(content))
    print("DEBUG -- email_parts:", email_parts)

    # Set Initial values
    combined_analysis = {"f_risk_score":0, "combined_reasons":[]}
    t_risk_score = 0
    n_analysis = 0 # Calulate the number of analysis
    f_risk_score = 0

    #1) Score & Reason
    #2) I need to call your function -> give me whats your intital function
    #3) tell me what you need e.g., URL

    # Function 1: Suspicious Keyword Checks on body
    subject_and_body = email_parts.get('subject', 'N/A') + '\n' + email_parts.get('body', 'N/A')
    score, reason = find_suspicious_keywords(subject_and_body)
    t_risk_score += score
    combined_analysis['combined_reasons'].append(reason)
    n_analysis += 1; 

    score, reason = assign_risk_score(subject=email_parts.get('subject', 'N/A'), body=email_parts.get('body', 'N/A'))
    t_risk_score += score
    combined_analysis['combined_reasons'].append(reason)
    n_analysis += 1; 
    
    # Function 2: Verify domain
    score, reason = check_whitelist(email=email_parts.get('sender_name','NA'), domain=email_parts.get('sender_domain','NA'))
    t_risk_score += score
    combined_analysis['combined_reasons'].append(reason)
    n_analysis += 1; 
    
    # Function 3: URL Check
    URL_list = email_parts.get('url', 'N/A')
    score, reason = check_url(URL_list)
    t_risk_score += score
    combined_analysis['combined_reasons'].append(reason)
    n_analysis += 1; 
    
    # Function 4: Sender Name/Display Name Check
    score, reason = check_sender_and_display_name(display_name=email_parts.get('display_name', 'N/A'), 
                                                   sender_name=email_parts.get('sender_name', 'N/A'), 
                                                   sender_domain=email_parts.get('sender_domain', 'N/A'))
    t_risk_score += score
    combined_analysis['combined_reasons'].append(reason)
    n_analysis += 1; 

    # Function 5: Domain Name check    
    score, reason = check_domain(email_domain=email_parts.get('sender_domain', 'N/A'))
    print("DEBUG -- score:", score)
    print("DEBUG -- reason:", reason)
    t_risk_score += score
    combined_analysis['combined_reasons'].append(reason)
    n_analysis += 1; 

    # Function 6: Finance detect
    score, reason = check_financial_request(content=email_parts.get('body', 'N/A'))
    t_risk_score += score
    combined_analysis['combined_reasons'].append(reason)
    n_analysis += 1; 
    
    
    # Calculate total risk score
    if t_risk_score !=0:
        f_risk_score = t_risk_score/n_analysis # Divide by total number of functions
        combined_analysis['f_risk_score'] = f_risk_score

    # Map the risk score to a conclusion and risk level. 
    if f_risk_score >= 81:
        c_suspicious_email += 1 # Consider as suspicious email
        c_cmf_phsihing += 1 # Add count to the number of confimred phsihing emails
        conclusion = "Phishing"
    elif f_risk_score >= 65:
        c_suspicious_email += 1 # Consider as suspicious email
        conclusion = "Moderately Suspicious"
    elif f_risk_score >= 50:
        c_suspicious_email += 1 # Consider as suspicious email
        conclusion = "Low Suspicious"
    else:
        c_safe_emails += 1 # Consider as safe email
        conclusion = "Safe"
    
    # Successfully scanned 1 email
    c_emails_analyse += 1 
     
    combined_analysis['conclusion'] = conclusion

    return {
        "score": round(f_risk_score, 1),
        "category": conclusion,
        "reasons": combined_analysis['combined_reasons'],
        "keyword_count": 'NA',
        "domain_reputation": 'NA'
    }
# ----------------------------
# Run the app
# ----------------------------
if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
    