import html
import re
import bleach


def validatePassword(password):
    if not isinstance(password, str):
        return False
    if len(password) < 8:
        return False
    if not re.search(r"[a-zA-Z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if len(password) > 255:
        return False
    return True


def validateEmail(email):
    if not isinstance(email, str):
        return False
    if not re.match(r"^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,4}$", email):
        return False
    if len(email) > 255:
        return False
    return True


def validateName(firstname, lastname):
    if not isinstance(firstname, str) or not isinstance(lastname, str):
        return False
    if len(firstname) > 16 or len(lastname) > 16:
        return False
    if not re.match(r"^[A-Za-z]+$", firstname) or not re.match(r"^[A-Za-z]+$", lastname):
        return False
    return True

def validateLog(title, body):
    if not isinstance(title, str):
        return False
    if len(title) > 64:
        return False
    if len(body) > 2048:
        return False
    return True


def sanitizeQuery(query):
    query = query.strip()
    query = query.replace('%', r'\%').replace('_', r'\_')
    query = query.replace(';', '')
    query = html.escape(query)
    if len(query) > 255:
        return query[:255]
    return query

# TinyMCE already has sanitisation
def sanitizeLog(body):
    allowed_tags = set(bleach.sanitizer.ALLOWED_TAGS)
    allowed_tags.update(['p', 'br', 'span', 'div', 'strong', 'em', 'ul', 'ol', 'li', 'blockquote', 'pre'])
    allowed_attributes = bleach.sanitizer.ALLOWED_ATTRIBUTES
    allowed_attributes.update({
        'span': [],
        'div': [],
        'p': [],
        'strong': [],
        'em': [],
        'ul': [],
        'ol': [],
        'li': [],
        'blockquote': [],
        'pre': [],
    })
    safe_body = bleach.clean(body, tags=allowed_tags, attributes=allowed_attributes)
    return safe_body
