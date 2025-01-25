import html


def validateCredentials(password):
    if not isinstance(password, str):
        return False
    return True


def sanitize(string: str) -> str:
    return html.escape(string)
