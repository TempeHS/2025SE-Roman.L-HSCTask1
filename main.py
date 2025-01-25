from datetime import datetime, timedelta # Date and time
from urllib.parse import urlparse # URL parsing
import logging
import requests
from flask import Flask, redirect, render_template, request, session, url_for, make_response, jsonify
from flask_wtf import CSRFProtect
from flask_csp.csp import csp_header
from flask_limiter import Limiter # Rate limiter
from flask_limiter.util import get_remote_address # Rate limiter
from markupsafe import Markup # Devlog formatting
from src import sanitize_and_validate as sv, session_state as sst, password_hashing as psh # Custom modules
import userManagement as dbHandler # Database functions
import ssl # SSL context


app_log = logging.getLogger(__name__)
logging.basicConfig(
    filename="security_log.log",
    encoding="utf-8",
    level=logging.DEBUG,
    format="%(asctime)s %(message)s",
)


app = Flask(__name__)
# CSRF
app.secret_key = b"f53oi3uriq9pifpff;apl"
csrf = CSRFProtect(app)
# 30d expiration
app.permanent_session_lifetime = timedelta(days=30)
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_HTTPONLY=True
)

def nl2br(value):
    return Markup(value.replace('\n', '\n'))

app.jinja_env.filters['nl2br'] = nl2br

# Default rate limiter
"""
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)
"""

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
        "style-src": "'self' 'unsafe-inline' https://fonts.googleapis.com",
        "script-src": "'self' 'unsafe-inline' 'unsafe-eval'",
        "img-src": "'self' data:",
        "media-src": "'self'",
        "font-src": "'self' https://fonts.gstatic.com data: https://fonts.googleapis.com",
        "object-src": "'self'",
        "child-src": "'self'",
        "connect-src": "'self'",
        "worker-src": "'self'",
        "report-uri": "/csp_report",
        "frame-ancestors": "'none'",
        "form-action": "'self'",
        "frame-src": "'none'"
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
@sst.logoutRequired
def signup():
    '''
    Signup page for new users
    '''
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "").replace('\\', '/')
        parsed_url = urlparse(url)
        if not parsed_url.scheme and not parsed_url.netloc:
            return redirect(url, code=302)
        return redirect('/', code=302)
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        firstName = request.form["firstName"]
        lastName = request.form["lastName"]

        if dbHandler.userExists(email) or not sv.validateCredentials(
            password
        ):
            print("User exists or invalid credentials")
            return redirect(url_for('signup'))

        dbHandler.insertUser(email, password, firstName, lastName)
        return render_template("/index.html")
    return render_template("/signup.html")


@app.route("/index.html", methods=["GET", "POST"])
#@limiter.limit("5 per day")
@sst.logoutRequired
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
        email = request.form["email"]
        password = request.form["password"]

        user = dbHandler.retrieveUsers(email)
        if user and psh.verifyPassword(password, user[2]):
            session.permanent = True
            session['user_id'] = user[0]
            session['email'] = email
            session['logged_in'] = True

            app_log.info("Successful login: %s", email)
            logs = dbHandler.listDevlogs()
            return render_template("/dashboard.html", logs=logs, value=user[0], state=True)
        else:
            app_log.warning("Failed login attempt: %s | %s | %s",
                            email, request.remote_addr, datetime.now())

    return redirect(url_for('index'))


@app.route("/form.html", methods=["GET", "POST"])
@sst.loginRequired
def form():
    '''
    Form page for posting, login required
    '''
    if request.method == "POST":
        title = request.form["title"]
        body = request.form["body"]
        user_id = session.get('user_id')
        user = dbHandler.getUserById(user_id)
        email = user[1]
        fullname = f"{user[3]} {user[4]}"
        current_date = datetime.now().strftime("%Y-%m-%d %H:%M")
        dbHandler.insertDevlog(title, body, fullname, email, current_date)
        return redirect(url_for('dashboard'))
    return render_template("/form.html")


@app.route("/dashboard.html", methods=["GET", "POST"])
@sst.loginRequired
def dashboard():
    '''
    Dashboard for logged in users
    '''
    logs = dbHandler.listDevlogs()
    return render_template('/dashboard.html', logs=logs)


@app.route('/logout', methods=['POST'])
@sst.loginRequired
def logout():
    '''
    Logout for logged in
    '''
    session.clear()
    return redirect('/index.html')


@app.route('/search')
@sst.loginRequired
def search():
    query = request.args.get('query', '')
    filter_type = request.args.get('filter', 'all')
    if filter_type == 'developer':
        logs = dbHandler.searchByDeveloper(query)
    elif filter_type == 'date':
        logs = dbHandler.searchByDate(query)
    elif filter_type == 'content':
        logs = dbHandler.searchByContent(query)
    else:
        logs = dbHandler.searchAll(query)
    return render_template('dashboard.html', logs=logs)


# Endpoint for logging CSP violations
@app.route("/csp_report", methods=["POST"])
@csrf.exempt
def csp_report():
    app.logger.critical(request.data.decode())
    return "done"


context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('certs/certificate.pem', 'certs/privatekey.pem')

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=443)
