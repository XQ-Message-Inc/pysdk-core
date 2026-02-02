import pytest
from unittest.mock import MagicMock, patch, mock_open
from xq.api.manage.authentication import *
import xq.api.subscription.user_management as um
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5


from xq.api.subscription.user_management import *


@patch('xq.api.subscription.user_management._load_or_use_content')
@patch('xq.api.subscription.user_management.AESEncryption')
@patch('xq.api.subscription.user_management._rsa_decrypt_with_crypto')
def test_login_certificate_success(mock_rsa_decrypt, mock_aes, mock_load_file,  mock_xqapi):
    # Setup mock file contents
    mock_load_file.side_effect = ["mock_cert", "mock_transport_key", "mock_private_key"]

    # Setup API responses
    mock_xqapi.api_get = MagicMock(return_value=(200, "1234567890"))

    # Setup encrypted response
    mock_response_data = {"access_token": "decrypted_access_token",
                          "ask": base64.b64encode(b"encrypted_ask").decode()}
    encrypted_response = base64.b64encode(json.dumps(mock_response_data).encode()).decode()
    mock_xqapi.api_post = MagicMock(return_value=(200, encrypted_response))

    # Setup AES encryption/decryption - FIXED: return actual bytes
    mock_aes_instance = MagicMock()
    mock_aes_instance.encrypt.return_value = b"mock_encrypted_bytes"  # Return bytes, not MagicMock
    mock_aes_instance.decrypt.return_value = json.dumps(mock_response_data).encode()
    mock_aes.return_value = mock_aes_instance

    # Setup RSA decryption
    mock_rsa_decrypt.return_value = b"decrypted_ask"

    result = login_certificate(
        mock_xqapi,
        cert_id=123,
        cert_file_path="client.crt",
        transport_key_file_path="transport.key",
        private_key_file_path="client.key",
        device_name="test_device"
    )

    assert result == "decrypted_access_token"


def test_login_certificate_invalid_device_name(mock_xqapi):
    with pytest.raises(XQException) as exc_info:
        login_certificate(mock_xqapi, 123, "client.crt", "transport.key", "client.key", "")
    assert "Device name must be provided" in str(exc_info.value)


@patch('xq.api.subscription.user_management._load_or_use_content')
def test_login_certificate_file_load_error(mock_load_file, mock_xqapi):
    mock_load_file.side_effect = XQException("File not found")

    with pytest.raises(XQException):
        login_certificate(
            mock_xqapi, 123, "client.crt", "transport.key", "client.key", "test_device"
        )


@patch('xq.api.subscription.user_management._load_or_use_content')
@patch('xq.api.subscription.user_management.AESEncryption')
def test_login_certificate_api_time_error(mock_aes, mock_load_file, mock_xqapi):
    mock_load_file.side_effect = ["mock_cert", "mock_transport_key", "mock_private_key"]

    mock_aes_instance = MagicMock()
    mock_aes_instance.encrypt.return_value = b"mock_encrypted_bytes"
    mock_aes.return_value = mock_aes_instance

    mock_xqapi.api_get = MagicMock(return_value=(500, "server error"))

    with pytest.raises(XQException) as exc_info:
        login_certificate(
            mock_xqapi, 123, "client.crt", "transport.key", "client.key", "test_device"
        )
    assert "Failed to get server time" in str(exc_info.value)


def test_create_certificate_200(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(200, "mock server success"))
    assert create_certificate(
        mock_xqapi, tag="New Certificate", fence=["192.168.0.1"], enabled=True
    )


def test_create_certificate_error(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        create_certificate(
            mock_xqapi, tag="New Certificate", fence=["192.168.0.1"], enabled=True
        )


def test_delete_certificate_200(mock_xqapi):
    mock_xqapi.api_delete = MagicMock(return_value=(204, "mock server success"))
    assert delete_certificate(mock_xqapi, id=1)


def test_delete_certificate_error(mock_xqapi):
    mock_xqapi.api_delete = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        delete_certificate(mock_xqapi, id=1)


def test_authorize_user_200(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(200, {"code": ""}))
    assert authorize_user(mock_xqapi, email="usr@xq.com")


def test_authorize_user_error(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        assert authorize_user(mock_xqapi, email="usr@xq.com")


def test_authorize_alias_200(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(200, "mock server success"))
    assert authorize_alias(mock_xqapi, email="usr@xq.com")


def test_authorize_alias_error(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        assert authorize_alias(mock_xqapi, email="usr@xq.com")


def test_load_or_use_content_with_file():
    """Test _load_or_use_content loads from file when file exists"""
    mock_content = "file content here"
    with patch("builtins.open", mock_open(read_data=mock_content)), \
            patch("os.path.exists", return_value=True):
        result = um._load_or_use_content("test_file.txt")
        assert result == mock_content


def test_load_or_use_content_with_direct_value():
    """Test _load_or_use_content uses direct value when file doesn't exist"""
    direct_value = "direct_content_here"
    with patch("os.path.exists", return_value=False):
        result = um._load_or_use_content(direct_value)
        assert result == direct_value


def test_load_or_use_content_file_read_error():
    """Test _load_or_use_content raises XQException on file read error"""
    with patch("os.path.exists", return_value=True), \
            patch("builtins.open", side_effect=PermissionError("Permission denied")):
        with pytest.raises(XQException) as exc_info:
            um._load_or_use_content("restricted_file.txt")
        assert "Failed to read file" in str(exc_info.value)


def test_normalize_transport_key_success():
    assert um._normalize_transport_key("  abc123  ") == "abc123"


def test_normalize_transport_key_empty_raises():
    with pytest.raises(XQException, match="No transport key"):
        um._normalize_transport_key("   ")


def test_rsa_decrypt_with_crypto_pem_roundtrip():
    key = RSA.generate(2048)
    private_pem = key.export_key().decode("utf-8")
    public = key.publickey()
    cipher = PKCS1_v1_5.new(public)

    plaintext = b"super secret"
    ct = cipher.encrypt(plaintext)

    pt = um._rsa_decrypt_with_crypto(private_pem, ct)
    assert pt == plaintext
