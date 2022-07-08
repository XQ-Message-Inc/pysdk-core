from pydoc import plain
import pytest
import docx
from io import BytesIO
from xq.algorithms.otp_encryption import *

# support function for reading docx file content
def readDocx(filename):
    doc = docx.Document(filename)
    fullText = []
    for para in doc.paragraphs:
        fullText.append(para.text)
    return "\n".join(fullText)


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


def test_roundtrip_fh(tmp_path, key_bytes):
    file_content = "some text to encrypt"

    with open(f"{tmp_path}/filetoencrypt", "w") as fh_write:
        fh_write.write(file_content)

    fh_read = open(f"{tmp_path}/filetoencrypt", "r")

    otp = OTPEncryption(key_bytes)
    ciphertext = otp.encrypt(fh_read)
    plaintext = otp.decrypt(ciphertext)

    assert plaintext == file_content


# test binary file
def test_roundtrip_bytesfile(key_bytes, binaryFilelike):
    otp = OTPEncryption(key_bytes)
    ciphertext = otp.encrypt(binaryFilelike)
    plaintext = otp.decrypt(ciphertext)

    assert plaintext == binaryFilelike.getvalue().decode()


# test docx file
def test_roundtrip_bytesfile(tmpdir, key_bytes, docxFilePath):
    docxFileHandle = open(docxFilePath, "rb")

    otp = OTPEncryption(key_bytes)
    ciphertext = otp.encrypt(docxFileHandle)
    decrypted_bytes = otp.decrypt(ciphertext)

    # write bytes to file
    with open(f"{tmpdir}/temp.docx", "wb") as fh:
        fh.write(decrypted_bytes)

        assert "hello world" == readDocx(f"{tmpdir}/temp.docx")


# test docx file bytes
def test_roundtrip_bytesfile(key_bytes, docxFilePath):
    docxBytes = open(docxFilePath, "rb").read()

    otp = OTPEncryption(key_bytes)

    # assert False
    ciphertext = otp.encrypt(docxBytes, encoding="CP437")
    decrypted_bytes = otp.decrypt(ciphertext, encoding="CP437")

    assert decrypted_bytes == docxBytes


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
