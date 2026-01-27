import pytest
import xq.api.subscription.user_management as um
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from unittest.mock import MagicMock, patch, mock_open

from xq.api.subscription.user_management import *

def test_authorize_user_200(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(200, "mock server success"))
    assert authorize_user(mock_xqapi, "mockuser@xq.com", "Mock", "Mocker")


def test_authorize_user_error(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(500, "mock server error"))
    assert authorize_user(mock_xqapi, "mockuser@xq.com", "Mock", "Mocker") is False


def test_authorize_alias_200(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(200, "mock server success"))
    assert authorize_alias(mock_xqapi, "mockuser@xq.com", "Mock", "Mocker")


def test_authorize_alias_error(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(500, "mock server error"))
    assert authorize_alias(mock_xqapi, "mockuser@xq.com", "Mock", "Mocker") is False

def test_authorize_device_success(mock_xqapi):
    # Mock the encrypted response
    mock_token_data = {"access_token": "mock_access_token"}
    encrypted_payload = base64.b64encode(json.dumps(mock_token_data).encode()).decode()
    
    mock_xqapi.api_post = MagicMock(return_value=(200, encrypted_payload))
    mock_xqapi.locator_key = "mock_locator_key"
    
    with patch('xq.api.subscription.user_management.AESEncryption') as mock_aes, \
         patch('xq.api.subscription.user_management.announce_device') as mock_announce:
        
        mock_aes_instance = MagicMock()
        mock_aes_instance.decrypt.return_value = json.dumps(mock_token_data).encode()
        mock_aes.return_value = mock_aes_instance
        mock_announce.return_value = 200
        
        result = authorize_device(mock_xqapi, "test_device", "business_123")
        
        assert result == "mock_access_token"
        mock_announce.assert_called_once_with(mock_xqapi, afirst="test_device")


def test_authorize_device_no_business_id(mock_xqapi):
    with pytest.raises(XQException) as exc_info:
        authorize_device(mock_xqapi, "test_device", None)
    assert "Please provide a business_id" in str(exc_info.value)


def test_authorize_device_api_error(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(500, "server error"))
    result = authorize_device(mock_xqapi, "test_device", "business_123")
    assert result is False


@patch('xq.api.subscription.user_management.load_file_content')
@patch('xq.api.subscription.user_management.announce_device')
@patch('xq.api.subscription.user_management.AESEncryption')
@patch('xq.api.subscription.user_management._rsa_decrypt_with_crypto')
def test_authorize_device_cert_success(mock_rsa_decrypt, mock_aes, mock_announce, mock_load_file, mock_xqapi):
    # Setup mock file contents
    mock_load_file.side_effect = ["mock_cert", "mock_transport_key", "mock_private_key"]
    
    # Setup API responses
    mock_xqapi.api_get = MagicMock(return_value=(200, "1234567890"))
    
    # Setup encrypted response
    mock_response_data = {"access_token": base64.b64encode(b"encrypted_token").decode()}
    encrypted_response = base64.b64encode(json.dumps(mock_response_data).encode()).decode()
    mock_xqapi.api_post = MagicMock(return_value=(200, encrypted_response))
    
    # Setup AES encryption/decryption - FIXED: return actual bytes
    mock_aes_instance = MagicMock()
    mock_aes_instance.encrypt.return_value = b"mock_encrypted_bytes"  # Return bytes, not MagicMock
    mock_aes_instance.decrypt.return_value = json.dumps(mock_response_data).encode()
    mock_aes.return_value = mock_aes_instance
    
    # Setup RSA decryption
    mock_rsa_decrypt.return_value = b"decrypted_access_token"
    
    # Setup announce device
    mock_announce.return_value = 200
    
    result = authorize_device_cert(
        mock_xqapi, 
        cert_id=123, 
        cert_file_path="client.crt", 
        transport_key_file_path="transport.key",
        private_key_file_path="client.key",
        device_name="test_device"
    )
    
    assert result == "decrypted_access_token"
    mock_announce.assert_called_once_with(mock_xqapi, afirst="test_device")


def test_authorize_device_cert_invalid_device_name(mock_xqapi):
    with pytest.raises(XQException) as exc_info:
        authorize_device_cert(mock_xqapi, 123, "client.crt", "transport.key", "client.key", "")
    assert "Device name must be provided" in str(exc_info.value)
    
    with pytest.raises(XQException) as exc_info:
        authorize_device_cert(mock_xqapi, 123, "client.crt", "transport.key", "client.key", "x" * 49)
    assert "cannot exceed 48 characters" in str(exc_info.value)


@patch('xq.api.subscription.user_management.load_file_content')
def test_authorize_device_cert_file_load_error(mock_load_file, mock_xqapi):
    mock_load_file.side_effect = XQException("File not found")
    
    with pytest.raises(XQException):
        authorize_device_cert(
            mock_xqapi, 123, "client.crt", "transport.key", "client.key", "test_device"
        )


@patch('xq.api.subscription.user_management.load_file_content')
@patch('xq.api.subscription.user_management.AESEncryption')
def test_authorize_device_cert_api_time_error(mock_aes, mock_load_file, mock_xqapi):
    mock_load_file.side_effect = ["mock_cert", "mock_transport_key", "mock_private_key"]
    
    mock_aes_instance = MagicMock()
    mock_aes_instance.encrypt.return_value = b"mock_encrypted_bytes"
    mock_aes.return_value = mock_aes_instance
    
    mock_xqapi.api_get = MagicMock(return_value=(500, "server error"))
    
    with pytest.raises(XQException) as exc_info:
        authorize_device_cert(
            mock_xqapi, 123, "client.crt", "transport.key", "client.key", "test_device"
        )
    assert "Failed to load certificate or key files" in str(exc_info.value)

def test_load_file_content_success():
    mock_content = "file content here"
    with patch("builtins.open", mock_open(read_data=mock_content)):
        result = load_file_content("test_file.txt")
        assert result == mock_content


def test_load_file_content_file_not_found():
    with patch("builtins.open", side_effect=FileNotFoundError):
        with pytest.raises(XQException) as exc_info:
            load_file_content("nonexistent_file.txt")
        assert "File not found" in str(exc_info.value)


def test_load_file_content_general_error():
    with patch("builtins.open", side_effect=PermissionError("Permission denied")):
        with pytest.raises(XQException) as exc_info:
            load_file_content("restricted_file.txt")
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


def test_exchange_for_subscription_token_success(mock_xqapi):
    mock_subscription_token = "xyz123"
    mock_xqapi.api_get = MagicMock(return_value=(200, mock_subscription_token))
    mock_xqapi.set_api_auth_token = MagicMock()
    original_auth = "Bearer dashboard_token"
    mock_xqapi.headers = {"authorization": original_auth}
    
    result = exchange_for_subscription_token(mock_xqapi)
    
    assert result == mock_subscription_token
    mock_xqapi.set_api_auth_token.assert_called_once_with(mock_subscription_token)
    mock_xqapi.api_get.assert_called_once_with(
        "exchange",
        subdomain="subscription",
        params={"request": "dashboard"}
    )

    assert mock_xqapi.headers["authorization"] == original_auth


def test_exchange_for_subscription_token_error_401(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(401, "Unauthorized"))
    mock_xqapi.headers = {"authorization": "Bearer invalid_dashboard_token"}
    
    with pytest.raises(XQException) as exc_info:
        exchange_for_subscription_token(mock_xqapi)
    assert "Failed to exchange token: 401" in str(exc_info.value)


def test_exchange_for_subscription_token_error_403(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(403, "Forbidden"))
    mock_xqapi.headers = {"authorization": "Bearer dashboard_token"}
    
    with pytest.raises(XQException) as exc_info:
        exchange_for_subscription_token(mock_xqapi)
    assert "Failed to exchange token: 403" in str(exc_info.value)


def test_exchange_for_subscription_token_error_500(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(500, "Internal Server Error"))
    mock_xqapi.headers = {"authorization": "Bearer dashboard_token"}
    
    with pytest.raises(XQException) as exc_info:
        exchange_for_subscription_token(mock_xqapi)
    assert "Failed to exchange token: 500" in str(exc_info.value)


def test_exchange_for_subscription_token_preserves_original_auth(mock_xqapi):
    original_auth = "Bearer original_dashboard_token"
    mock_xqapi.api_get = MagicMock(return_value=(500, "Server error"))
    mock_xqapi.headers = {"authorization": original_auth}
    
    try:
        exchange_for_subscription_token(mock_xqapi)
    except XQException:
        pass
    
    assert mock_xqapi.headers["authorization"] == original_auth


def test_exchange_for_subscription_token_no_original_auth(mock_xqapi):
    """Test exchange when there's no original authorization header"""
    mock_subscription_token = "new_subscription_token"
    mock_xqapi.api_get = MagicMock(return_value=(200, mock_subscription_token))
    mock_xqapi.set_api_auth_token = MagicMock()
    mock_xqapi.headers = {}  # No authorization header
    
    result = exchange_for_subscription_token(mock_xqapi)
    
    assert result == mock_subscription_token
    # Verify token was set via the method
    mock_xqapi.set_api_auth_token.assert_called_once_with(mock_subscription_token)

    assert mock_xqapi.headers["authorization"] == f"Bearer {mock_subscription_token}"