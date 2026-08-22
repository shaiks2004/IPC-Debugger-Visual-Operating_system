import os
from base64 import urlsafe_b64encode

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend


def derive_key_from_password(password: str, salt: bytes = None, iterations: int = 100_000):
    """
    If salt is None -> generate random salt and return (key, salt)
    If salt is provided -> return key
    """
    if salt is None:
        salt = os.urandom(16)
        new_salt = True
    else:
        new_salt = False

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    )
    key = urlsafe_b64encode(kdf.derive(password.encode()))
    if new_salt:
        return key, salt
    return key


class SecureChannel:
    """Small wrapper around Fernet to encrypt/decrypt text messages."""

    def __init__(self, key: bytes = None):
        self.key = key if key is not None else Fernet.generate_key()
        self._fernet = Fernet(self.key)

    def encrypt(self, text: str) -> bytes:
        return self._fernet.encrypt(text.encode())

    def decrypt(self, data: bytes) -> str:
        return self._fernet.decrypt(data).decode()


def compute_hmac(key: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()


def verify_hmac(key: bytes, data: bytes, tag: bytes) -> bool:
    try:
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(data)
        h.verify(tag)
        return True
    except Exception:
        return False
