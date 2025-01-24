from datetime import datetime, timedelta
import logging
import requests
from flask import Flask, redirect, render_template, request, session, jsonify
from flask_wtf import CSRFProtect
from flask_csp.csp import csp_header
from src import sanitize_and_validate as sv, session_state as sst, password_hashing as psh
import userManagement as dbHandler


app_log = logging.getLogger(__name__)
logging.basicConfig(
    filename="security_log.log",
    encoding="utf-8",
    level=logging.DEBUG,
    format="%(asctime)s %(message)s",
)


app = Flask(__name__)
app.permanent_session_lifetime = timedelta(days=30)
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_HTTPONLY=True
)
app.secret_key = b"f53oi3uriq9pifpff;apl"
csrf = CSRFProtect(app)


# Redirect index.html to domain root for consistent UX
@app.route("/index", methods=["GET"])
@app.route("/index.htm", methods=["GET"])
@app.route("/index.asp", methods=["GET"])
@app.route("/index.php", methods=["GET"])
@app.route("/index.html", methods=["GET"])
def root():
    return redirect("/", 302)


@app.route("/", methods=["POST", "GET"])
@csp_header(
    {
        # Server Side CSP is consistent with meta CSP in layout.html
        "base-uri": "'self'",
        "default-src": "'self'",
        "style-src": "'self'",
        "script-src": "'self'",
        "img-src": "'self' data:",
        "media-src": "'self'",
        "font-src": "'self'",
        "object-src": "'self'",
        "child-src": "'self'",
        "connect-src": "'self'",
        "worker-src": "'self'",
        "report-uri": "/csp_report",
        "frame-ancestors": "'none'",
        "form-action": "'self'",
        "frame-src": "'none'",
    }
)


def index():
    '''
    Landing page when user is not logged in
    '''
    if session.get('logged_in'):
        return redirect('/dashboard.html')
    return render_template("/index.html")


@app.route("/privacy.html", methods=["GET"])
def privacy():
    '''
    Privacy policy page
    '''
    return render_template("/privacy.html")


@app.route("/signup.html", methods=["GET", "POST"])
@sst.logout_required
def signup():
    '''
    Signup page for new users
    '''
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return redirect(url, code=302)
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if dbHandler.userExists(username) or not sv.validateCredentials(
            username, password
        ):
            print("User exists or invalid credentials")
            return render_template("/signup.html")

        dbHandler.insertUser(username, password)
        return render_template("/index.html")
    return render_template("/signup.html")


@app.route("/index.html", methods=["GET", "POST"])
@sst.logout_required
def login():
    '''
    Login page for new users
    '''
    if session.get('logged_in'):
        return redirect('/dashboard.html')
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return redirect(url, code=302)
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = dbHandler.retrieveUsers(username)
        if user and psh.verifyPassword(password, user[2]):
            session.permanent = True
            session['user_id'] = user[0]
            session['username'] = username
            session['logged_in'] = True
            logs = dbHandler.listDevlogs()
            return render_template("/dashboard.html", logs=logs, value=username, state=True)
    return render_template("/index.html")


@app.route("/form.html", methods=["GET", "POST"])
@sst.login_required
def form():
    '''
    Form page for posting, login required
    '''
    if request.method == "POST":
        title = request.form["title"]
        body = request.form["body"]
        username = session['username']
        current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        dbHandler.insertDevlog(title, body, username, current_date)
        return render_template("/dashboard.html")
    return render_template("/form.html")


@app.route("/dashboard.html", methods=["GET", "POST"])
@sst.login_required
def dashboard():
    '''
    Dashboard for logged in users
    '''
    logs = dbHandler.listDevlogs()
    return render_template('/dashboard.html', logs=logs)


@app.route('/logout', methods=['POST'])
@sst.login_required
def logout():
    '''
    Logout for logged out
    '''
    session.clear()
    return redirect('/index.html')


# Endpoint for logging CSP violations
@app.route("/csp_report", methods=["POST"])
@csrf.exempt
def csp_report():
    app.logger.critical(request.data.decode())
    return "done"


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
