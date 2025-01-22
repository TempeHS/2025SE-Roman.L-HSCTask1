import html


def validateCredentials(username, password):

    if not (1 <= len(username) <= 16 and username.isalpha()):
        return False

    if not isinstance(password, str):
        return False

    return True


def sanitize(string: str) -> str:
    return html.escape(string)
