from flask import Flask, render_template, request
import zipfile, io

# Import different functions that check for phishing signs in the email
from emailchecking_functions.keywords import check_keywords
from emailchecking_functions.links import check_links
from emailchecking_functions.greetings import check_greetings
from emailchecking_functions.urgency import check_urgency
from emailchecking_functions.punctuation import check_punctuation
from emailchecking_functions.personalinfo import check_personal_info
from emailchecking_functions.test import testingfunction
from emailchecking_functions.financedetect import check_financial_request
from Website.emailchecking_functions.keywords_and_whitelist import find_suspicious_keywords, check_whitelist

from emailchecking_functions.url_check_copy import check_url


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
        phishing=24,
        anothernumber=2000,
        sum=5,
        sus=5000
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

    # Pass results back to the template to display
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
    score, reasons = 0.0, []  # total score and reasons list
    keyword_count, domain_reputation = 0, "Good"
    
    # Run keyword checker
    kw_score, kw_reasons, keyword_count = check_keywords(content)
    score += kw_score; reasons += kw_reasons

    # Run link checker
    link_score, link_reasons, domain_reputation = check_links(content)
    score += link_score; reasons += link_reasons

    # Run greetings checker
    g_score, g_reasons = check_greetings(content)
    score += g_score; reasons += g_reasons

    # Run urgency checker
    u_score, u_reasons = check_urgency(content)
    score += u_score; reasons += u_reasons

    # Run punctuation checker
    p_score, p_reasons = check_punctuation(content)
    score += p_score; reasons += p_reasons

    # Run personal info checker
    pi_score, pi_reasons = check_personal_info(content)
    score += pi_score; reasons += pi_reasons;reasons 

    fi_score, fi_reasons = check_financial_request(content)
    score += fi_score; reasons += fi_reasons

    # angirena's URL check
    url_score, url_reasons = check_url(content)
    score += url_score; reasons += url_reasons 



    # Run test function (custom rules)
    test1, test2 = testingfunction(content)
    score += test1; reasons += test2

    zyscore, zyreason = find_suspicious_keywords(content)
    score += zyscore; reasons += zyreason

    zyscore2, zyreason2 = check_whitelist(content)
    score += zyscore2; reasons += zyreason2

    

    # Make sure score does not exceed 10
    score = min(score, 10)

    # Decide category based on score
    if score < 3:
        category = "Safe"
    elif score < 6:
        category = "Suspicious"
    else:
        category = "Phishing"

    # Return all results as dictionary
    return {
        "score": round(score, 1),
        "category": category,
        "reasons": reasons,
        "keyword_count": keyword_count,
        "domain_reputation": domain_reputation
    }

# ----------------------------
# Run the app
# ----------------------------
if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
