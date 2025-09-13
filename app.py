from flask import Flask, render_template

app = Flask(__name__)


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
            reason = f"the word {i} is very suspicous thats why it is being flagged out!!"

    return render_template("home.html",total_length=total_length,totalscore=totalscore,reason=reason)

    



if __name__ in "__main__":
    app.run(debug=True)
    # test
