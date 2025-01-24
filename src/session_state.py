from functools import wraps
from flask import redirect, session


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect("/index.html")
        return f(*args, **kwargs)
    return decorated_function


def logout_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("logged_in"):
            return redirect("/dashboard.html")
        return f(*args, **kwargs)
    return decorated_function
