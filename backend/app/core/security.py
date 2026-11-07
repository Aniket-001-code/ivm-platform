"""Request identifiers and at-rest protection for small secrets."""

import base64
import hashlib
from secrets import token_urlsafe

from cryptography.fernet import Fernet

from app.core.config import get_settings


def new_request_id() -> str:
    return token_urlsafe(12)


def _fernet() -> Fernet:
    key = base64.urlsafe_b64encode(
        hashlib.sha256(get_settings().secret_key.encode()).digest()
    )
    return Fernet(key)


def encrypt_secret(value: str) -> str:
    return "fernet:" + _fernet().encrypt(value.encode()).decode()


def decrypt_secret(value: str) -> str:
    if not value.startswith("fernet:"):
        return value
    return _fernet().decrypt(value.removeprefix("fernet:").encode()).decode()
