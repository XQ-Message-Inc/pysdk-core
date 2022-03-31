import pytest
from xq.algorithms.aes_encryption import *


@pytest.fixture()
def key():
    return b"yesthisissixteen"


@pytest.fixture()
def plaintextFixiture():
    return "this is a test"


def test_aes(key):
    aes = AESEncryption(key)
    assert aes


def test_roundtrip(key, plaintextFixiture):
    aes = AESEncryption(key)
    ciphertext, nonce, tag = aes.encrypt(plaintextFixiture)
    plaintext = aes.decrypt(ciphertext)

    assert plaintext == plaintextFixiture


def test_roundtrip_seperate_instances(key, plaintextFixiture):
    aes = AESEncryption(key)
    ciphertext, nonce, tag = aes.encrypt(plaintextFixiture)

    aes = AESEncryption(key, nonce=nonce)
    plaintext = aes.decrypt(ciphertext)

    assert plaintext == plaintextFixiture
