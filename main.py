# Standard Library Imports
import os
import ssl
import time
import html
import random
from datetime import datetime, timedelta # Date and time
from urllib.parse import urlparse, urljoin # URL parsing

# Third-Party Imports
from flask import Flask, redirect, render_template, request, session, url_for, jsonify, flash, g
from flask_wtf import CSRFProtect
from flask_csp.csp import csp_header
from flask_limiter import Limiter # Rate limiter
from flask_limiter.util import get_remote_address # Rate limiter
from flask_login import LoginManager, login_user, logout_user, login_required, current_user # Login manager
from apscheduler.schedulers.background import BackgroundScheduler
from dotenv import load_dotenv

# Local Application Imports
from src import sanitize_and_validate as sv, session_state as sst, password_hashing as psh # Custom modules
from src.config import app_log
import userManagement as dbHandler # Database functions
from userManagement import User # User management

load_dotenv()

app = Flask(__name__)

@app.before_request
def generate_nonce():
    g.nonce = os.urandom(16).hex()

# CSRF
# If .env does not load try:
# app.secret_key =   b"f53oi3uriq9pifpff;apl"
app.secret_key =  os.getenv('secret_key')
csrf = CSRFProtect(app)

scheduler = BackgroundScheduler()
scheduler.add_job(dbHandler.deleteUserByInactivity, 'interval', days=1)  # Run daily
scheduler.start()

# 30d expiration
app.permanent_session_lifetime = timedelta(days=30)
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True
)

@app.after_request
def add_cache_control(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    
    # Disable Cache
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# Default rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "100 per hour"],
    storage_uri="memory://",
)

@app.errorhandler(429)
def ratelimit_handler(e):
    flash("Rate limit exceeded. Please try again later.", "error")
    return redirect(url_for('index'))

# Login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    '''
    Load user by IDs
    '''
    return dbHandler.getUserById(user_id)

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

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
        "style-src": "'self' 'nonce-{{ g.nonce }}'",
        "script-src": "'self' 'nonce-{{ g.nonce }}'",
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
        "frame-src": "'none'"
    }
)

@sst.logout_required
def index():
    '''
    Landing page when user is not logged in
    '''
    return render_template("/index.html")


@app.route("/privacy.html", methods=["GET"])
def privacy():
    '''
    Privacy policy page
    '''
    return render_template("/privacy.html")


@app.route("/signup.html", methods=["GET", "POST"])
@limiter.limit("5 per day")
@sst.logout_required
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
        firstname = request.form["firstname"]
        lastname = request.form["lastname"]

        # Validate user input
        if dbHandler.userExists(email):
            flash('User already exists!', 'error')
            print("User already exists with this email")
            return redirect(url_for('signup'))
        if not sv.validatePassword(password):
            print("Invalid password format")
            return redirect(url_for('signup'))
        if not sv.validateEmail(email):
            print("Invalid email format")
            return redirect(url_for('signup'))
        if not sv.validateName(firstname, lastname):
            print("Invalid name format")
            return redirect(url_for('signup'))

        password = psh.hashPassword(password)
        firstname = firstname.capitalize()
        lastname = lastname.capitalize()
        dbHandler.insertUser(email, password, firstname, lastname)
        return render_template("/index.html")
    return render_template("/signup.html")


@app.route("/index.html", methods=["GET", "POST"])
#@limiter.limit("5 per day")
@sst.logout_required
def login():
    '''
    Login page for new users
    '''
    if request.method == "GET" and request.args.get("url"):
        target = request.args.get('url', '')
        target = target.replace('\\', '')
        if is_safe_url(target):
            return redirect(target, code=302)
        return redirect('/dashboard', code=302)
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        # Validate user input
        user = dbHandler.retrieveUsers(email)
        if user and psh.verifyPassword(password, user[2]):
            user_obj = User(user[0], user[1], user[3], user[4])
            login_user(user_obj)
            time.sleep(random.uniform(0.1, 0.2))
            app_log.info("Successful login: %s", email)
            dbHandler.updateLastActivity(user[0])
            logs = dbHandler.listDevlogs()
            return render_template("/dashboard.html", logs=logs)

        time.sleep(random.uniform(0.1, 0.2))
        app_log.warning("Failed login attempt: %s | %s | %s", email, request.remote_addr, datetime.now())
        flash("Invalid credentials.", "error")
    return redirect(url_for('index'))


@app.route("/form.html", methods=["GET", "POST"])
@limiter.limit("5 per day")
@login_required
def form():
    '''
    Form page for posting, login required
    '''
    if request.method == "POST":
        title = request.form["title"]
        body = request.form["body"]

        if not sv.validateLog(title, body):
            return redirect(url_for('form'))
        safe_title = html.escape(title)
        safe_body = sv.sanitizeLog(body)

        user_id = current_user.id
        user = dbHandler.getUserById(user_id)
        fullname = f"{user.firstname} {user.lastname}"
        current_date = datetime.now().strftime("%Y-%m-%d %H:%M")
        dbHandler.insertDevlog(safe_title, safe_body, fullname, user_id, current_date)
        app_log.info("New log created by %s: %s", user_id, title)
        return redirect(url_for('dashboard'))
    nonce = g.get("nonce", "")
    return render_template("/form.html", nonce=nonce)


@app.route("/dashboard.html", methods=["GET", "POST"])
@login_required
def dashboard():
    '''
    Dashboard for logged in users
    '''
    checkSessionTimeout()
    logs = dbHandler.listDevlogs()
    return render_template('/dashboard.html', logs=logs)


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    '''
    Logout for logged in
    '''
    logout_user()
    flash("You have been logged out.", "info")
    return redirect('/index.html')

@app.route('/search')
@login_required
def search():
    '''
    Search developer logs for logged in
    '''
    query = request.args.get('query', '')
    safe_query = sv.sanitizeQuery(query)
    filter_type = request.args.get('filter', 'all')
    if filter_type == 'developer':
        logs = dbHandler.searchByDeveloper(safe_query)
    elif filter_type == 'date':
        logs = dbHandler.searchByDate(safe_query)
    elif filter_type == 'content':
        logs = dbHandler.searchByContent(safe_query)
    else:
        logs = dbHandler.searchAll(safe_query)
    return render_template('dashboard.html', logs=logs)


@app.route('/delete_account', methods=['POST'])
@login_required
def deleteUser():
    '''
    Removes current user from database
    '''
    user_id = current_user.id
    try:
        dbHandler.deleteUserById(user_id)
        logout_user()
        app_log.info("Successful account deletion: %s", user_id)
        return redirect(url_for('index'))
    except Exception as e:
        app_log.error("Failed account deletion attempt %s: %s", user_id, str(e))
        flash("An error occurred while trying to delete your account. Please try again.", "error")
    return redirect(url_for('dashboard'))


@app.route('/delete_log', methods=['POST'])
@login_required
def deleteLog():
    '''
    Delete log from database
    '''
    user_id = current_user.id
    log_id = request.form.get('log_id')
    try:
        dbHandler.deleteLogs(user_id, log_id)
        app_log.info("Successful log deletion: %s: %s", user_id, log_id)
    except Exception as e:
        app_log.error("Failed log deletion attempt %s: %s", user_id, str(e))
        flash("An error occurred while trying to delete your log. Please try again.", "error")
    return redirect(url_for('dashboard'))


@app.route('/download_data', methods=['GET'])
@login_required
@limiter.limit("5 per day")
def downloadUser():
    '''
    Download user data as JSON
    '''
    user_id = request.args.get('user_id', type=int)
    if not user_id:
        return jsonify({"error": "Incorrect User"}), 400
    user = dbHandler.getUserById(user_id)
    if current_user.id != user_id:
        app_log.info("Unauthorized access %s: %s", current_user, user_id)
        return jsonify({"error": "User not found"}), 404

    user_data = {
        "user_id": user.id,
        "email": user.email,
        "firstname": user.firstname,
        "lastname": user.lastname,
    }

    response = jsonify(user_data)
    response.headers["Content-Disposition"] = f"attachment;filename=user_data_{user_id}.json"
    return response

# Endpoint for logging CSP violations
@app.route("/csp_report", methods=["POST"])
@csrf.exempt
def csp_report():
    '''
    Report CSP violations
    '''
    app.logger.critical(request.data.decode())
    return "done"


@app.before_request
def checkSessionTimeout():
    '''
    Session timeout check, 30 minutes
    '''
    if 'user_id' in session:
        last_activity = session.get('last_activity')
        if last_activity and datetime.now() - last_activity > timedelta(minutes=30):
            logout_user()
            return redirect(url_for('login'))
        session['last_activity'] = datetime.now()

## SSL Encryption
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('certs/certificate.pem', 'certs/privatekey.pem')

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
