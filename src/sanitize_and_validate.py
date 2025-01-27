import html
import re


def validateCredentials(password):
    if not isinstance(password, str):
        return False
    return True


def sanitize(string: str) -> str:
    return html.escape(string)


def convertLinks(text):
    url_pattern = r'(https?://[^\s]+)'
    return re.sub(url_pattern, r'<a href="\1" target="_blank">\1</a>', text)
