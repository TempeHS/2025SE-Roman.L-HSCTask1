from flask_wtf import CSRFProtect

csrf = CSRFProtect()

def init_security(app):
    """
    Initialize security-related configurations for the Flask app.
    """
    app.after_request(set_security_headers)


def set_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    return response
