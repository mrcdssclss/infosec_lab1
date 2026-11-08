"""Small security helpers, testable independently from Flask."""
import hmac
import html
import re
from werkzeug.security import generate_password_hash, check_password_hash

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,32}$")


def valid_username(username: object) -> bool:
    return isinstance(username, str) and bool(USERNAME_PATTERN.fullmatch(username))


def valid_password(password: object) -> bool:
    return isinstance(password, str) and 12 <= len(password) <= 128


def hash_password(password: str) -> str:
    return generate_password_hash(password, method="scrypt")


def verify_password(stored_hash: str, password: str) -> bool:
    return check_password_hash(stored_hash, password)


def safe_display(value: str) -> str:
    # Escape HTML-sensitive characters to prevent clients rendering raw text as markup.
    return html.escape(value, quote=True)
