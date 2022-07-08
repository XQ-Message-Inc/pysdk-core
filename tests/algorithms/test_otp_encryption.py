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


# # test docx file
# def test_roundtrip_bytesfile(key_bytes, docxFilePath):
#     docxFileHandle = open(docxFilePath, 'rb')

#     otp = OTPEncryption(key_bytes)
#     ciphertext = otp.encrypt(docxFileHandle)
#     plaintext = otp.decrypt(ciphertext)

#     assert 'hello world' == readDocx(plaintext)


# test docx file bytes
def test_roundtrip_bytesfile(key_bytes, docxFilePath):
    docxBytes = open(docxFilePath, "rb").read()

    otp = OTPEncryption(key_bytes)

    encode_list = [
        "ascii",
        "big5",
        "big5hkscs",
        "cp037",
        "cp273",
        "cp424",
        "cp437",
        "cp500",
        "cp720",
        "cp737",
        "cp775",
        "cp850",
        "cp852",
        "cp855",
        "cp856",
        "cp857",
        "cp858",
        "cp860",
        "cp861",
        "cp862",
        "cp863",
        "cp864",
        "cp865",
        "cp866",
        "cp869",
        "cp874",
        "cp875",
        "cp932",
        "cp949",
        "cp950",
        "cp1006",
        "cp1026",
        "cp1125",
        "cp1140",
        "cp1250",
        "cp1251",
        "cp1252",
        "cp1253",
        "cp1254",
        "cp1255",
        "cp1256",
        "cp1257",
        "cp1258",
        "euc_jp",
        "euc_jis_2004",
        "euc_jisx0213",
        "euc_kr",
        "gb2312",
        "gbk",
        "gb18030",
        "hz",
        "iso2022_jp",
        "iso2022_jp_1",
        "iso2022_jp_2",
        "iso2022_jp_2004",
        "iso2022_jp_3",
        "iso2022_jp_ext",
        "iso2022_kr",
        "latin_1",
        "iso8859_2",
        "iso8859_3",
        "iso8859_4",
        "iso8859_5",
        "iso8859_6",
        "iso8859_7",
        "iso8859_8",
        "iso8859_9",
        "iso8859_10",
        "iso8859_11",
        "iso8859_13",
        "iso8859_14",
        "iso8859_15",
        "iso8859_16",
        "johab",
        "koi8_r",
        "koi8_t",
        "koi8_u",
        "kz1048",
        "mac_cyrillic",
        "mac_greek",
        "mac_iceland",
        "mac_latin2",
        "mac_roman",
        "mac_turkish",
        "ptcp154",
        "shift_jis",
        "shift_jis_2004",
        "shift_jisx0213",
        "utf_32",
        "utf_32_be",
        "utf_32_le",
        "utf_16",
        "utf_16_be",
        "utf_16_le",
        "utf_7",
        "utf_8",
        "utf_8_sig",
    ]
    for encoding in encode_list:
        try:
            ciphertext = otp.encrypt(docxBytes, encoding)
            plaintext = otp.decrypt(ciphertext)
            print(encoding)
            assert "hello world" == readDocx(BytesIO(plaintext.encode(encoding)))
            print("\tPASSED!!!!!!")
        except Exception as e:
            print(f"\terror: {e}")
        pass

    assert False
    # ciphertext = otp.encrypt(docxBytes)
    # plaintext = otp.decrypt(ciphertext)

    # assert "hello world" == readDocx(plaintext)


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
