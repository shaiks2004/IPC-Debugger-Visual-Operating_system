from cryptography.fernet import Fernet

class SecureChannel:
    def __init__(self, key: bytes = None):
        if key is None:
            self.key = Fernet.generate_key()
        else:
            self.key = key
        self.cipher = Fernet(self.key)

    def encrypt(self, message: str) -> bytes:
        return self.cipher.encrypt(message.encode())

    def decrypt(self, data: bytes) -> str:
        return self.cipher.decrypt(data).decode()
