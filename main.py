from datetime import datetime, timedelta # Date and time
from urllib.parse import urlparse # URL parsing
import logging
import requests
from flask import Flask, redirect, render_template, request, session, url_for, make_response, after_this_request, jsonify, Response, send_file
from flask_wtf import CSRFProtect
from flask_csp.csp import csp_header
from flask_limiter import Limiter # Rate limiter
from flask_limiter.util import get_remote_address # Rate limiter
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user # Login manager
from markupsafe import Markup # Devlog formatting
from src import sanitize_and_validate as sv, session_state as sst, password_hashing as psh # Custom modules
import userManagement as dbHandler # Database functions
from userManagement import User # User management
import json # JSON parsing
import ssl # SSL context
from io import BytesIO # File handling


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

# New login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return dbHandler.getUserById(user_id)

# Default rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# Cache control headers
def disable_cache():
    '''
    Disable cache for all routes
    '''
    @after_this_request
    def add_no_cache(response):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

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
@login_manager.unauthorized_handler
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

        if dbHandler.userExists(email) or not sv.validateCredentials(
            password
        ):
            print("User exists or invalid credentials")
            return redirect(url_for('signup'))

        dbHandler.insertUser(email, password, firstname, lastname)
        return render_template("/index.html")
    return render_template("/signup.html")


@app.route("/index.html", methods=["GET", "POST"])
# @limiter.limit("5 per day")
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
        email = request.form["email"]
        password = request.form["password"]

        user = dbHandler.retrieveUsers(email)
        if user and psh.verifyPassword(password, user[2]):
            user_obj = User(user[0], user[1], user[3], user[4])
            login_user(user_obj)

            app_log.info("Successful login: %s", email)
            logs = dbHandler.listDevlogs()
            return render_template("/dashboard.html", logs=logs)
        app_log.warning("Failed login attempt: %s | %s | %s", email, request.remote_addr, datetime.now())
    return redirect(url_for('index'))


@app.route("/form.html", methods=["GET", "POST"])
@login_required
def form():
    '''
    Form page for posting, login required
    '''
    if request.method == "POST":
        title = request.form["title"]
        body = request.form["body"]
        user_id = current_user.id
        user = dbHandler.getUserById(user_id)
        email = user.email
        fullname = f"{user.firstname} {user.lastname}"
        current_date = datetime.now().strftime("%Y-%m-%d %H:%M")
        dbHandler.insertDevlog(title, body, fullname, email, current_date)
        return redirect(url_for('dashboard'))
    return render_template("/form.html")


@app.route("/dashboard.html", methods=["GET", "POST"])
@login_required
def dashboard():
    '''
    Dashboard for logged in users
    '''
    logs = dbHandler.listDevlogs()
    return render_template('/dashboard.html', logs=logs)


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    '''
    Logout for logged in
    '''
    logout_user()
    return redirect('/index.html')


@app.route('/search')
@login_required
def search():
    '''
    Search developer logs for logged in
    '''
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


@app.route('/delete_account', methods=['POST'])
@login_required
def deleteUser():
    '''
    Removes user from database
    '''
    user_id = current_user.id
    try:
        dbHandler.deleteUserById(user_id)
        logout_user()
        app_log.info("Successful account deletion: %s", user_id)
        return redirect(url_for('index'))
    except Exception as e:
        app_log.error("Failed account deletion attempt %s: %s", user_id, str(e))
        return "An error occurred while trying to delete your account. Please try again.", 500

@app.route('/download_data', methods=['GET'])
@login_required
#@limiter.limit("5 per day")
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
        "id": user.id,
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

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('certs/certificate.pem', 'certs/privatekey.pem')

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=443)
