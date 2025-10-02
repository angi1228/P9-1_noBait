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

# ----------------------------
# Home Page
# ----------------------------
@app.route("/")
def home():
    # When you open the main page, show index.html
    # Some sample values (phishing, anothernumber, etc.) are sent to template
    return render_template(
        "index.html",
        phishing=0,
        anothernumber=0,
        sum=0,
        sus=0
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
        score=result['score'],
        category=result['category'],
        reasons=result['reasons'],
        keyword_count=result['keyword_count'],
        domain_reputation=result['domain_reputation'],
        email_content=email_content,
        anothernumber=2000, sum=5, sus=5000
       
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
            return render_template("index.html", zip_results=results,
                                   phishing=24, anothernumber=2000, sum=5, sus=5000)

        else:
            # If uploaded file is just a single email file (not zip)
            content = file.read().decode('utf-8', errors='ignore')
            result = analyze_email_content_detailed(content)
            return render_template("index.html",
                                   filename=file.filename,
                                   email_content=content,
                                   **result)

    except Exception as e:
        # If something goes wrong, show error
        return render_template("index.html", error=f"Error processing file: {str(e)}")

# ----------------------------
# Main Analyzer - combines all checks
# ----------------------------
def analyze_email_content_detailed(content: str):

    # 1. Get Constants before running the analysis
    email_parts = extract_email_parts(content) # Returns the email parts 
    
    combined_analysis = {"risk_score":t_risk_score, "reaons":[]}
    t_risk_score = 0
    ## {
    #   "score": 89,
    #   "reasons": ["A", "B", "C"]
    #   } 
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
    score, reasons = Levenshtein_homoglyphs_domains(normmalised_sender_domain)
    t_risk_score += score; n_analysis += 1
    combined_analysis.append(reasons)


    ''' TO AMEND THE FOLLOWING'''
    # ## Final result (Combine all scores and reasons)
    # #1: score, 2>: reasons

    # score, reasons = 0.0, []  # total score and reasons list
    # keyword_count, domain_reputation = 0, "Good"
    
    # # Run keyword checker
    # kw_score, kw_reasons, keyword_count = check_keywords(content)
    # score += kw_score; reasons += kw_reasons

    # # Run link checker
    # link_score, link_reasons, domain_reputation = check_links(content)
    # score += link_score; reasons += link_reasons

    # # Run greetings checker
    # g_score, g_reasons = check_greetings(content)
    # score += g_score; reasons += g_reasons

    # # Run urgency checker
    # u_score, u_reasons = check_urgency(content)
    # score += u_score; reasons += u_reasons

    # # Run punctuation checker
    # p_score, p_reasons = check_punctuation(content)
    # score += p_score; reasons += p_reasons

    # # Run personal info checker
    # pi_score, pi_reasons = check_personal_info(content)
    # score += pi_score; reasons += pi_reasons;reasons 

    # fi_score, fi_reasons = check_financial_request(content)
    # score += fi_score; reasons += fi_reasons


    # # Run test function (custom rules)
    # test1, test2 = testingfunction(content)
    # score += test1; reasons += test2

    ''' STOP AMENDING HERE '''


    # Map the risk score to a conclusion and risk level. 
    if score >= 81:
        conclusion, risk_level = "Phishing", "High"
    elif score >= 65:
        conclusion, risk_level = "Moderately Suspicious", "Medium"
    elif score >= 50:
        conclusion, risk_level = "Low Suspicious", "Low"
    else:
        conclusion, risk_level = "Safe", "Safe"

    # Return all results as dictionary
    # return {
    #     "score": round(score, 1),
    #     "category": category,
    #     "reasons": reasons,
    #     "keyword_count": keyword_count,
    #     "domain_reputation": domain_reputation
    # }

    return {
        'title': "Phishing Alert: File Scan Result", # Replace with actual subject
        'sender_email': f"{sender_name} (File Scan)",
        'sender_name': sender_name,
        'risk_score': final_score,
        'reason': prelim_data['prelim_reason'] + f" | Domain Score: {domain_check_result}",
        'conclusion': conclusion,
        'time_of_scan': datetime.now().strftime("%I:%M %p, %b %d"),
        'risk_level': risk_level # For internal tracking/CSS
    }

# ----------------------------
# Run the app
# ----------------------------
if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
