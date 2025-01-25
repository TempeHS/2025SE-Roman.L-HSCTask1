from functools import wraps
from flask import redirect, session


def loginRequired(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect("/index.html")
        return f(*args, **kwargs)
    return decorated_function


def logoutRequired(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("logged_in"):
            return redirect("/dashboard.html")
        return f(*args, **kwargs)
    return decorated_function
