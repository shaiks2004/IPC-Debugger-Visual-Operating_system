#remberinfads the HMac are the keys for the code
import os
from base64 import urlsafe_b64encode, urlsafe_b64decode

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend

# Derive a Fernet-compatible key from a password.
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
        backend=default_backend()
    )
    key = urlsafe_b64encode(kdf.derive(password.encode()))
    # return both when new salt, useful for storage/transport if you later want to reuse
    if new_salt:
        return key, salt
    return key

class SecureChannel:
    """
    Small wrapper around Fernet to encrypt/decrypt text messages.
    The key should be a urlsafe_b64encoded 32-byte key (what Fernet uses).
    """
    def __init__(self, key: bytes = None):
        if key is None:
            self.key = Fernet.generate_key()
        else:
            self.key = key
        self._fernet = Fernet(self.key)

    def encrypt(self, text: str) -> bytes:
        return self._fernet.encrypt(text.encode())

    def decrypt(self, data: bytes) -> str:
        return self._fernet.decrypt(data).decode()

# HMAC helpers to authenticate ciphertext (integrity + origin)
def compute_hmac(key: bytes, data: bytes) -> bytes:
    """
    Compute HMAC-SHA256 using 'key' as the HMAC key.
    Note: key should be bytes. We accept Fernet key as-is.
    """
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
