from pydoc import plain
from pypdf import PdfReader
import pytest
import docx
from io import BytesIO
from xq.algorithms.otp_encryption import *


def test_otp(key_bytes):
    otp = OTPEncryption(key_bytes)
    assert otp


def test_roundtrip(key_bytes, plaintextFixiture):
    otp = OTPEncryption(key_bytes)
    ciphertext, expanded_key = otp.encrypt(plaintextFixiture)
    plaintext = otp.decrypt(ciphertext)

    assert plaintext == plaintextFixiture.encode()


def test_roundtrip_seperate_instances(key_bytes, plaintextFixiture):
    otp = OTPEncryption(key_bytes)
    ciphertext, expanded_key = otp.encrypt(plaintextFixiture)

    otp = OTPEncryption(key_bytes)
    plaintext = otp.decrypt(ciphertext)

    assert plaintext == plaintextFixiture.encode()


# test file
def test_roundtrip_file(key_bytes, plaintextFilelike):
    otp = OTPEncryption(key_bytes)
    ciphertext, expanded_key = otp.encrypt(plaintextFilelike)
    plaintext = otp.decrypt(ciphertext)

    assert plaintext == plaintextFilelike.getvalue().encode()


def test_roundtrip_seperate_instances_file(key_bytes, plaintextFilelike):
    with pytest.warns(UserWarning):
        otp = OTPEncryption(key_bytes)
        ciphertext, expanded_key = otp.encrypt(plaintextFilelike)

        expandedKey = otp.key

        otp = OTPEncryption(expandedKey)
        plaintext = otp.decrypt(ciphertext)

        assert plaintext == plaintextFilelike.getvalue().encode()


def test_roundtrip_fh(tmp_path, key_bytes):
    file_content = b"some text to encrypt"

    with open(f"{tmp_path}/filetoencrypt", "wb") as fh_write:
        fh_write.write(file_content)

    fh_read = open(f"{tmp_path}/filetoencrypt", "rb")

    otp = OTPEncryption(key_bytes)
    ciphertext, expanded_key = otp.encrypt(fh_read)
    plaintext = otp.decrypt(ciphertext)

    assert plaintext == file_content


# test binary file
def test_roundtrip_bytesfile(key_bytes, binaryFilelike):
    otp = OTPEncryption(key_bytes)
    ciphertext, expanded_key = otp.encrypt(binaryFilelike)
    plaintext = otp.decrypt(ciphertext)

    assert plaintext == binaryFilelike.getvalue()


# support function for reading docx file content
def readDocx(filename):
    doc = docx.Document(filename)
    fullText = []
    for para in doc.paragraphs:
        fullText.append(para.text)
    return "\n".join(fullText)


# test docx file
def test_roundtrip_docxfile(tmpdir, key_bytes, docxFilePath):
    docxFileHandle = open(docxFilePath, "rb")

    otp = OTPEncryption(key_bytes)
    ciphertext, expanded_key = otp.encrypt(docxFileHandle)
    decrypted_bytes = otp.decrypt(ciphertext)

    # write bytes to file
    with open(f"{tmpdir}/temp.docx", "wb") as fh:
        fh.write(decrypted_bytes)

        assert "hello world" == readDocx(f"{tmpdir}/temp.docx")


# test docx file bytes
def test_roundtrip_docxbytes(key_bytes, docxFilePath):
    docxBytes = open(docxFilePath, "rb").read()

    otp = OTPEncryption(key_bytes)

    # assert False
    ciphertext, expanded_key = otp.encrypt(docxBytes)
    decrypted_bytes = otp.decrypt(ciphertext)

    assert decrypted_bytes == docxBytes


# support function for reading pdf file content
def readPDF(filename):
    with open(filename, "rb") as fh:
        pdfReader = PdfReader(fh)
        pageObj = pdfReader.pages[0]
        return pageObj.extract_text()


# test pdf file
def test_roundtrip_pdffile(tmpdir, key_bytes, pdfFilePath):
    docxFileHandle = open(pdfFilePath, "rb")

    otp = OTPEncryption(key_bytes)
    ciphertext, expanded_key = otp.encrypt(docxFileHandle)
    decrypted_bytes = otp.decrypt(ciphertext)

    # write bytes to file
    with open(f"{tmpdir}/temp.pdf", "wb") as fh:
        fh.write(decrypted_bytes)

        assert "hello world " == readPDF(f"{tmpdir}/temp.pdf")


# test pdf file bytes
def test_roundtrip_pdfbytes(key_bytes, pdfFilePath):
    pdfBytes = open(pdfFilePath, "rb").read()

    otp = OTPEncryption(key_bytes)

    # assert False
    ciphertext, expanded_key = otp.encrypt(pdfBytes)
    decrypted_bytes = otp.decrypt(ciphertext)

    assert decrypted_bytes == pdfBytes


def test_roundtrip_seperate_instances_bytesfile(key_bytes, binaryFilelike):
    otp = OTPEncryption(key_bytes)
    ciphertext, expanded_key = otp.encrypt(binaryFilelike)
    plaintext = otp.decrypt(ciphertext)

    assert plaintext == binaryFilelike.getvalue()


# test large files, over key length
def test_roundtrip_seperate_instances_bytesfile(key_bytes, largePlaintextFilelike):
    otp = OTPEncryption(key_bytes)
    ciphertext, expanded_key = otp.encrypt(largePlaintextFilelike)
    plaintext = otp.decrypt(ciphertext)

    assert plaintext == largePlaintextFilelike.getvalue()


def test_roundtrip_seperate_instances_bytesfile(key_bytes, largeBinaryFilelike):
    otp = OTPEncryption(key_bytes)
    ciphertext, expanded_key = otp.encrypt(largeBinaryFilelike)
    plaintext = otp.decrypt(ciphertext)

    assert plaintext == largeBinaryFilelike.getvalue()
