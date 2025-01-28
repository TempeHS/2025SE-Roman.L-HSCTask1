import html
import re


def validateCredentials(password):
    if not isinstance(password, str):
        return False
    if len(password) < 8:
        return False
    if not re.search(r"[a-zA-Z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    return True


def sanitize(string: str) -> str:
    return html.escape(string)


def sanitizeQuery(query):
    query = query.strip()
    query = query.replace('%', r'\%').replace('_', r'\_') 
    query = query.replace(';', '')
    query = html.escape(query)
    if len(query) > 255:
        raise ValueError("Search query is too long.")
    return query


def convertLinks(text):
    url_pattern = r'(https?://[^\s]+)'
    return re.sub(url_pattern, r'<a href="\1" target="_blank">\1</a>', text)
