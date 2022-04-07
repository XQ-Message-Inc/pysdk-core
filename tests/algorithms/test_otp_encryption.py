import pytest
from xq.algorithms.otp_encryption import *


def test_otp(key_bytes):
    otp = OTPEncryption(key_bytes)
    assert otp


def test_roundtrip(key_bytes, plaintextFixiture):
    otp = OTPEncryption(key_bytes)
    ciphertext = otp.encrypt(plaintextFixiture)
    plaintext = otp.decrypt(ciphertext)

    assert plaintext == plaintextFixiture


def test_roundtrip_seperate_instances(key_bytes, plaintextFixiture):
    otp = OTPEncryption(key_bytes)
    ciphertext = otp.encrypt(plaintextFixiture)

    otp = OTPEncryption(key_bytes)
    plaintext = otp.decrypt(ciphertext)

    assert plaintext == plaintextFixiture


# test file
def test_roundtrip_file(key_bytes, plaintextFilelike):
    otp = OTPEncryption(key_bytes)
    ciphertext = otp.encrypt(plaintextFilelike)
    plaintext = otp.decrypt(ciphertext)

    assert plaintext == plaintextFilelike.getvalue()


def test_roundtrip_seperate_instances_file(key_bytes, plaintextFilelike):
    with pytest.warns(UserWarning):
        otp = OTPEncryption(key_bytes)
        ciphertext = otp.encrypt(plaintextFilelike)

        expandedKey = otp.key

        otp = OTPEncryption(expandedKey)
        plaintext = otp.decrypt(ciphertext)

        assert plaintext == plaintextFilelike.getvalue()


# test binary file
def test_roundtrip_bytesfile(key_bytes, binaryFilelike):
    otp = OTPEncryption(key_bytes)
    ciphertext = otp.encrypt(binaryFilelike)
    plaintext = otp.decrypt(ciphertext)

    assert plaintext == binaryFilelike.getvalue().decode()


def test_roundtrip_seperate_instances_bytesfile(key_bytes, binaryFilelike):
    with pytest.warns(UserWarning):
        otp = OTPEncryption(key_bytes)
        ciphertext = otp.encrypt(binaryFilelike)

        expandedKey = otp.key

        otp = OTPEncryption(expandedKey)
        plaintext = otp.decrypt(ciphertext)

        assert plaintext == binaryFilelike.getvalue().decode()


# test large files, over key length
def test_roundtrip_seperate_instances_bytesfile(key_bytes, largePlaintextFilelike):
    with pytest.warns(UserWarning):
        otp = OTPEncryption(key_bytes)
        ciphertext = otp.encrypt(largePlaintextFilelike)

        expandedKey = otp.key

        otp = OTPEncryption(expandedKey)
        plaintext = otp.decrypt(ciphertext)

        assert plaintext == largePlaintextFilelike.getvalue()


def test_roundtrip_seperate_instances_bytesfile(key_bytes, largeBinaryFilelike):
    with pytest.warns(UserWarning):
        otp = OTPEncryption(key_bytes)
        ciphertext = otp.encrypt(largeBinaryFilelike)

        expandedKey = otp.key

        otp = OTPEncryption(expandedKey)
        plaintext = otp.decrypt(ciphertext)

        assert plaintext == largeBinaryFilelike.getvalue().decode()
