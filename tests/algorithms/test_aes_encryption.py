import pytest
import tempfile
import io
from xq.algorithms.aes_encryption import *

def test_aes(key_bytes):
    aes = AESEncryption(key_bytes)
    assert aes

# Fixtures for test setup
@pytest.fixture
def encryption_key():
    return b'some_secret_key'

@pytest.fixture
def aes_encryptor(encryption_key):
    return AESEncryption(encryption_key)

def test_aes(key_bytes):
    aes = AESEncryption(key_bytes)
    assert aes

def test_add_header_salt(aes_encryptor):
    result = aes_encryptor.add_header_salt()
    assert isinstance(result, dict)
    assert 'header' in result
    assert 'salt' in result
    assert 'iv' in result
    assert len(result['salt']) == 16
    assert len(result['iv']) == 12

def test_derive_key(aes_encryptor):
    salt = os.urandom(16)
    password = b'test_password'
    derived_key = aes_encryptor.derive_key(salt, password)
    assert len(derived_key) == 32 

def test_encrypt_decrypt(aes_encryptor):
    plaintext = "This is a test"
    password = "password123"
    encrypted_data = aes_encryptor.encrypt(plaintext, password)
    assert isinstance(encrypted_data, bytearray)

    decrypted_data = aes_encryptor.decrypt(encrypted_data, password)
    assert decrypted_data == plaintext

def test_encrypt_decrypt_with_default_key(aes_encryptor):
    plaintext = "This is another test"
    encrypted_data = aes_encryptor.encrypt(plaintext)
    decrypted_data = aes_encryptor.decrypt(encrypted_data)
    assert decrypted_data == plaintext

def test_invalid_data_format_for_decrypt(aes_encryptor):
    with pytest.raises(ValueError):
        aes_encryptor.decrypt(b'invalid data format')

def test_roundtrip(key_bytes, plaintextFixiture):
    aes = AESEncryption(key_bytes)
    ciphertext = aes.encrypt(plaintextFixiture)
    plaintext = aes.decrypt(ciphertext)

    assert plaintext == plaintextFixiture

def test_roundtrip_seperate_instances(key_bytes, plaintextFixiture):
    aes = AESEncryption(key_bytes)
    ciphertext= aes.encrypt(plaintextFixiture)

    aes = AESEncryption(key_bytes)
    plaintext = aes.decrypt(ciphertext)

    assert plaintext == plaintextFixiture

def test_create_file_header(aes_encryptor):
    with tempfile.NamedTemporaryFile(suffix=".testfilename.txt", delete=False) as temp_file:
        filename = temp_file.name

    token = "testtoken" 
    token = token.ljust(43, 'x')
    
    version = 1

    print(f"Filename: {filename}, Token: {token}, Version: {version}")

    header = aes_encryptor.create_file_header(filename, token, version)

    print(f"Header: {header}")
    print(f"Buffer Length in pytest: {len(header)}")

def test_encryptFile_decryptFile(aes_encryptor):
    with tempfile.NamedTemporaryFile(suffix=".testfilename.txt", delete=False) as temp_file:
        temp_file.write(b"File data for encryption")
        temp_file.flush() 
        temp_file.seek(0)
        filename = temp_file.name

    file_data = b"File data for encryption"

    file_like_object = io.BytesIO(file_data)

    token = "token_string".ljust(43, 'x')
    password = "file_password"

    encrypted_file = aes_encryptor.encryptFile(filename, file_like_object, token, password)

    decrypted_file_data = aes_encryptor.decryptFile(encrypted_file, password)

    assert decrypted_file_data == file_data