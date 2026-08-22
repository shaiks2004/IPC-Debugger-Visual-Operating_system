from modules.secure_utils import SecureChannel, compute_hmac, derive_key_from_password, verify_hmac


def test_derive_key_stable_with_same_salt():
    key1, salt = derive_key_from_password("pass123")
    key2 = derive_key_from_password("pass123", salt=salt)
    assert key1 == key2


def test_encrypt_decrypt_roundtrip():
    sc = SecureChannel()
    msg = "hello secure ipc"
    enc = sc.encrypt(msg)
    assert sc.decrypt(enc) == msg


def test_hmac_verification_detects_tampering():
    key = SecureChannel().key
    data = b"abc123"
    tag = compute_hmac(key, data)
    assert verify_hmac(key, data, tag) is True
    tampered = b"abc124"
    assert verify_hmac(key, tampered, tag) is False
