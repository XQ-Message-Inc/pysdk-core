import pytest
from unittest.mock import MagicMock, patch, mock_open

from xq.api.subscription.user_management import *
from xq.api.manage.authentication import *



@patch('xq.api.subscription.user_management.AESEncryption')
@patch('xq.api.subscription.user_management._rsa_decrypt_with_crypto')
def login_certificate_success(mock_rsa_decrypt, mock_aes, mock_announce, mock_load_file, mock_xqapi):
    # Setup mock file contents
    
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
    

    
    result = login_certificate(
        mock_xqapi, 
        cert_id=123,
        cert_data="client.crt",
        transport_key="transpor.key",
        private_key="client.key",
        device_name="test_device"
    )
    
    assert result == "decrypted_access_token"
    mock_announce.assert_called_once_with(mock_xqapi, afirst="test_device")


def login_certificate_invalid_device_name(mock_xqapi):
    with pytest.raises(XQException) as exc_info:
        login_certificate(mock_xqapi, 123, "client.crt", "transport.key", "client.key", "")
    assert "Device name must be provided" in str(exc_info.value)
    
    with pytest.raises(XQException) as exc_info:
        authorize_device_cert(mock_xqapi, 123, "client.crt", "transport.key", "client.key", "x" * 49)
    assert "cannot exceed 48 characters" in str(exc_info.value)


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