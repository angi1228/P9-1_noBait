from flask import Flask, render_template, request
import zipfile, io
from datetime import datetime

# Import different functions that check for phishing signs in the email
from emailchecking_functions.keywords import check_keywords
from emailchecking_functions.links import check_links
from emailchecking_functions.greetings import check_greetings
from emailchecking_functions.urgency import check_urgency
from emailchecking_functions.punctuation import check_punctuation
from emailchecking_functions.personalinfo import check_personal_info
from emailchecking_functions.test import testingfunction
from emailchecking_functions.financedetect import check_financial_request

### Connecting the files together
from Constants import extract_email_parts
from Levenshtein_homoglyphs import Levenshtein_homoglyphs_domains 


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
        anothernumber=c_safe_emails,
        sum=c_emails_analyse,
        sus=c_suspicious_email
    )

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
    return render_template(
        "index.html",
        score=result['f_risk_score'],
        category=result['category_risk'],
        reasons=result['reasons'],
        keyword_count=result['keyword_count'],
        domain_reputation=result['domain_reputation'],
        email_content=email_content,
        phishing=c_cmf_phsihing,
        anothernumber=c_safe_emails,
        sum=c_emails_analyse,
        sus=c_suspicious_email
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
                    # Only process email-like files
                    if name.lower().endswith(('.eml', '.txt', '.html')):
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
                # score=result['risk_score'],
                # category=result['category_risk'],
                # reasons=result['reasons'],
                # keyword_count=result['keyword_count'],
                # domain_reputation=result['domain_reputation'],
                email_content=content,
                phishing=c_cmf_phsihing,
                anothernumber=c_safe_emails,
                sum=c_emails_analyse,
                sus=c_suspicious_email
            )


        else:
            # If uploaded file is just a single email file (not zip)
            content = file.read().decode('utf-8', errors='ignore')
            result = analyze_email_content_detailed(content)
            return render_template("index.html",
                                   filename=file.filename,
                                   email_content=content,
                                   **result)
            #    Pass results back to the template to display ## NOTE: YX To link from here
            return render_template(
                "index.html",
                
                score=result['f_risk_score'],
                category=result['conclusion'],
                reasons=result['combined_reasons'],
                keyword_count="N/A (Reverted to New Analyzer)",
                domain_reputation="N/A (Reverted to New Analyzer)",
                email_content=content,
                phishing=c_cmf_phsihing,
                anothernumber=c_safe_emails,
                sum=c_emails_analyse,
                sus=c_suspicious_email
            )


    except Exception as e:
        # If something goes wrong, show error
        return render_template("index.html", error=f"Error processing file: {str(e)}")

# ----------------------------
# Main Analyzer - combines all checks
# ----------------------------



def analyze_email_content_detailed(content: str):

    # 1. Get Constants before running the analysis
    email_parts = extract_email_parts(content) # Returns the email parts 
    
    combined_analysis = {"f_risk_score":0, "combined_reasons":[]}
    t_risk_score = 0
    n_analysis = 0 # Calulate the number of analysis

    # Function 1: Suspicious Keyword Checks????
    
    # Function 2: Verify domain
    
    # Function 3: URL Check
    
    # Function 4: keyword check????
    
    # Function 5: Sender Name/Display Name Check
    email_address = email_parts.get('email_address', 'N/A')
    normalised_display_name = email_parts.get('display_name', 'N/A').lower() # normalised
    normalised_sender_name = email_address.split("@")[0].lower()

    # Function 6: Domain Name check    
    normmalised_sender_domain = email_address.split("@")[-1].lower()
    score, reason = Levenshtein_homoglyphs_domains(normmalised_sender_domain)
    t_risk_score += score
    combined_analysis['combined_reasons'].append(reason)
    n_analysis += 1; 

    # Calculate total risk score
    f_risk_score = t_risk_score/n_analysis # Divide by total number of functions
    combined_analysis['f_risk_score'].update(f_risk_score)

    # Map the risk score to a conclusion and risk level. 
    if f_risk_score >= 81:
        c_suspicious_email += 1 # Consider as suspicious email
        cmf_phsihing += 1 # Add count to the number of confimred phsihing emails
        conclusion, risk_level = "Phishing", "High"
    elif f_risk_score >= 65:
        c_suspicious_email += 1 # Consider as suspicious email
        conclusion, risk_level = "Moderately Suspicious", "Medium"
    elif f_risk_score >= 50:
        c_suspicious_email += 1 # Consider as suspicious email
        conclusion, risk_level = "Low Suspicious", "Low"
    else:
        c_safe_emails += 1 # Consider as safe email
        conclusion, risk_level = "Safe", "Safe"
    
    # Successfully scanned 1 email
    c_emails_analyse += 1 
     
    combined_analysis['conclusion'] = conclusion
    combined_analysis['risk_level'] = risk_level

    combined_analysis.append['title'] = email_parts.get('email_address', 'N/A')
    combined_analysis.append['sender_email'] = email_parts.get('email_address', 'N/A')
    combined_analysis.append['sender_name'] = email_parts.get('display_name', 'N/A')
    combined_analysis.append['time_of_scan'] = datetime.now().strftime("%I:%M %p, %b %d")
    # print(combined_analysis) #NOTE: TO TEST ONI

    return combined_analysis 
    # {
    #     'title': email_parts.get('email_address', 'N/A'),
    #     'sender_email': f"{email_parts.get('email_address', 'N/A')} (File Scan)",
    #     'sender_name': email_parts.get('display_name', 'N/A'),
    #     'risk_score': combined_analysis['f_risk_score'],
    #     'reason': prelim_data['prelim_reason'] + f" | Domain Score: {domain_check_result}",
    #     'category_risk': conclusion,
    #     'time_of_scan': datetime.now().strftime("%I:%M %p, %b %d"),
    #     'risk_level': risk_level # For internal tracking/CSS
    # }

        # "index.html",
        # score=result['score'],
        # category=result['category'],
        # reasons=result['reasons'],
        # keyword_count=result['keyword_count'],
        # domain_reputation=result['domain_reputation'],
        # email_content=email_content,
        # anothernumber=2000, 
        # sum=5, 
        # sus=5000

# ----------------------------
# Run the app
# ----------------------------
if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
    