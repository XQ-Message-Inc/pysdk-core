import pytest
from xq.algorithms.aes_encryption import *


def test_aes(key_bytes):
    aes = AESEncryption(key_bytes)
    assert aes


def test_roundtrip(key_bytes, plaintextFixiture):
    aes = AESEncryption(key_bytes)
    ciphertext, nonce, tag = aes.encrypt(plaintextFixiture)
    plaintext = aes.decrypt(ciphertext)

    assert plaintext == plaintextFixiture


def test_roundtrip_seperate_instances(key_bytes, plaintextFixiture):
    aes = AESEncryption(key_bytes)
    ciphertext, nonce, tag = aes.encrypt(plaintextFixiture)

    aes = AESEncryption(key_bytes, nonce=nonce)
    plaintext = aes.decrypt(ciphertext)

    assert plaintext == plaintextFixiture


def test_bad_tag(key_bytes, plaintextFixiture):
    with pytest.raises(SDKEncryptionException):
        aes = AESEncryption(key_bytes)
        ciphertext, nonce, tag = aes.encrypt(plaintextFixiture)

        aes = AESEncryption(key_bytes, nonce=nonce)
        plaintext = aes.decrypt(ciphertext, verificationTag=b"badtag")
