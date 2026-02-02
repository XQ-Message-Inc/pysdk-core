from sys import exc_info
import pytest
import tempfile
import os
from unittest.mock import MagicMock

from xq.api.manage.authentication import *
from xq.exceptions import XQException


def test_dashboard_signup(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(204, "mock server success"))
    assert dashboard_signup(mock_xqapi, email="mockuser@xqtest.com")


def test_dashboard_signup_error(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        dashboard_signup(mock_xqapi, email="mockuser@xqtest.com")


def test_dashboard_signup_param_error(mock_xqapi):
    with pytest.raises(TypeError):
        dashboard_signup(mock_xqapi)


def test_generate_device_certificate_success(mock_xqapi):
    """Test successful device certificate generation without file output"""
    mock_response = {
        "id": 123,
        "transportKey": "dHJhbnNwb3J0S2V5QmFzZTY0RW5jb2RlZA==",
        "clientCert": "Y2xpZW50Q2VydEJhc2U2NEVuY29kZWQ=",
        "clientKey": "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCm1vY2tfa2V5X2Jhc2U2NAotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0t"
    }
    mock_xqapi.api_post = MagicMock(return_value=(200, mock_response))
    
    result = generate_device_certificate(mock_xqapi, tag="test_device")
    
    assert result == mock_response
    assert result["id"] == 123
    assert result["transportKey"] == "dHJhbnNwb3J0S2V5QmFzZTY0RW5jb2RlZA=="
    assert result["clientCert"] == "Y2xpZW50Q2VydEJhc2U2NEVuY29kZWQ="
    mock_xqapi.api_post.assert_called_once()
    call_args = mock_xqapi.api_post.call_args
    assert call_args[1]["json"]["tag"] == "test_device"
    assert call_args[1]["json"]["enabled"] is True
    assert call_args[1]["json"]["fence"] == []


def test_generate_device_certificate_with_fence(mock_xqapi):
    """Test device certificate generation with fence parameter"""
    mock_response = {
        "id": 456,
        "transportKey": "dHJhbnNwb3J0X2tleV9iYXNlNjQ=",
        "clientCert": "Y2xpZW50X2NlcnRfYmFzZTY0",
        "clientKey": "Y2xpZW50X2tleV9iYXNlNjQ="
    }
    mock_xqapi.api_post = MagicMock(return_value=(200, mock_response))
    
    fence = ["scope1", "scope2"]
    result = generate_device_certificate(
        mock_xqapi, 
        tag="fenced_device",
        fence=fence,
        enabled=False
    )
    
    assert result == mock_response
    call_args = mock_xqapi.api_post.call_args
    assert call_args[1]["json"]["fence"] == fence
    assert call_args[1]["json"]["enabled"] is False


def test_generate_device_certificate_with_output_dir(mock_xqapi):
    """Test device certificate generation with file output to directory"""
    mock_response = {
        "id": 789,
        "transportKey": "dHJhbnNwb3J0X2NvbnRlbnRfYmFzZTY0",
        "clientCert": "Y2VydF9jb250ZW50X2Jhc2U2NA==",
        "clientKey": "a2V5X2NvbnRlbnRfYmFzZTY0"
    }
    mock_xqapi.api_post = MagicMock(return_value=(200, mock_response))
    
    with tempfile.TemporaryDirectory() as tmpdir:
        result = generate_device_certificate(
            mock_xqapi,
            tag="file_device",
            output_dir=tmpdir
        )
        
        # Check files were created
        assert os.path.exists(os.path.join(tmpdir, "client.key"))
        assert os.path.exists(os.path.join(tmpdir, "client.crt"))
        assert os.path.exists(os.path.join(tmpdir, "transport.key"))
        
        # Check file contents (base64 format preserved)
        with open(os.path.join(tmpdir, "client.key")) as f:
            assert f.read() == "a2V5X2NvbnRlbnRfYmFzZTY0"
        with open(os.path.join(tmpdir, "client.crt")) as f:
            assert f.read() == "Y2VydF9jb250ZW50X2Jhc2U2NA=="
        with open(os.path.join(tmpdir, "transport.key")) as f:
            assert f.read() == "dHJhbnNwb3J0X2NvbnRlbnRfYmFzZTY0"
        
        assert result == mock_response


def test_generate_device_certificate_with_custom_paths(mock_xqapi):
    """Test device certificate generation with custom file paths"""
    mock_response = {
        "id": 999,
        "transportKey": "Y3VzdG9tX3RyYW5zcG9ydF9iYXNlNjQ=",
        "clientCert": "Y3VzdG9tX2NlcnRfYmFzZTY0",
        "clientKey": "Y3VzdG9tX2tleV9iYXNlNjQ="
    }
    mock_xqapi.api_post = MagicMock(return_value=(200, mock_response))
    
    with tempfile.TemporaryDirectory() as tmpdir:
        custom_key_path = os.path.join(tmpdir, "custom_client.key")
        custom_cert_path = os.path.join(tmpdir, "custom_client.crt")
        custom_transport_path = os.path.join(tmpdir, "custom_transport.key")
        
        result = generate_device_certificate(
            mock_xqapi,
            tag="custom_device",
            client_key_path=custom_key_path,
            client_cert_path=custom_cert_path,
            transport_key_path=custom_transport_path
        )
        
        # Check custom files were created
        assert os.path.exists(custom_key_path)
        assert os.path.exists(custom_cert_path)
        assert os.path.exists(custom_transport_path)
        
        with open(custom_key_path) as f:
            assert f.read() == "Y3VzdG9tX2tleV9iYXNlNjQ="
        with open(custom_cert_path) as f:
            assert f.read() == "Y3VzdG9tX2NlcnRfYmFzZTY0"
        with open(custom_transport_path) as f:
            assert f.read() == "Y3VzdG9tX3RyYW5zcG9ydF9iYXNlNjQ="


def test_generate_device_certificate_output_dir_creates_directory(mock_xqapi):
    """Test that output_dir creates directory if it doesn't exist"""
    mock_response = {
        "id": 111,
        "transportKey": "dF9rZXlfYmFzZTY0",
        "clientCert": "Y19jZXJ0X2Jhc2U2NA==",
        "clientKey": "Y19rZXlfYmFzZTY0"
    }
    mock_xqapi.api_post = MagicMock(return_value=(200, mock_response))
    
    with tempfile.TemporaryDirectory() as tmpdir:
        new_dir = os.path.join(tmpdir, "new_subdir")
        assert not os.path.exists(new_dir)
        
        generate_device_certificate(
            mock_xqapi,
            tag="mkdir_device",
            output_dir=new_dir
        )
        
        # Check directory was created
        assert os.path.exists(new_dir)
        assert os.path.exists(os.path.join(new_dir, "client.key"))


def test_generate_device_certificate_error_response(mock_xqapi):
    """Test error handling when API returns non-200 status"""
    mock_xqapi.api_post = MagicMock(return_value=(403, "Forbidden"))
    
    with pytest.raises(XQException) as exc_info:
        generate_device_certificate(mock_xqapi, tag="error_device")
    assert "Error generating device certificate" in str(exc_info.value)


def test_generate_device_certificate_missing_required_param(mock_xqapi):
    """Test that tag parameter is required"""
    with pytest.raises(TypeError):
        generate_device_certificate(mock_xqapi)


def test_send_login_link(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(204, "mock server success"))
    assert send_login_link(mock_xqapi, email="mockuser@xqtest.com")


def test_send_login_link_error(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        send_login_link(mock_xqapi, email="mockuser@xqtest.com")


def test_dashboard_login_oauth(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(200, "mock server success"))
    assert dashboard_login(mock_xqapi, password="mockpass", method=1)


def test_dashboard_login_creds(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(200, "mock server success"))
    assert dashboard_login(mock_xqapi, email="mocker@xqtest.com", password="mockpass")


def test_dashboard_login_creds_missing(mock_xqapi):
    with pytest.raises(TypeError):
        dashboard_login(mock_xqapi, method=0)


def test_dashboard_login_error(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(TypeError):
        dashboard_login(mock_xqapi)


def test_login_verify(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(200, "mock server success"))
    login_verify(mock_xqapi)


def test_login_verify_error(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        login_verify(mock_xqapi)


def test_validate_access_token(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(204, "mock server success"))
    validate_access_token(mock_xqapi)


def test_validate_access_token_error(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        validate_access_token(mock_xqapi)

def test_announce_device_success_200(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=200)
    result = announce_device(mock_xqapi, afirst="TestDevice")
    assert result == 200


def test_announce_device_success_204(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=204)
    result = announce_device(mock_xqapi, afirst="TestDevice")
    assert result == 204


def test_announce_device_with_all_params(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=200)
    result = announce_device(
        mock_xqapi, 
        afirst="TestDevice", 
        alast="LastName", 
        aphone="123-456-7890"
    )
    assert result == 200
    
    # Verify the correct payload was sent
    mock_xqapi.api_post.assert_called_once()
    call_args = mock_xqapi.api_post.call_args
    assert call_args[1]["json"]["afirst"] == "TestDevice"
    assert call_args[1]["json"]["alast"] == "LastName"
    assert call_args[1]["json"]["aphone"] == "123-456-7890"


def test_announce_device_default_params(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=200)
    result = announce_device(mock_xqapi)
    assert result == 200
    
    # Verify default empty values were sent
    call_args = mock_xqapi.api_post.call_args
    assert call_args[1]["json"]["afirst"] == ""
    assert call_args[1]["json"]["alast"] == ""
    assert call_args[1]["json"]["aphone"] == ""


def test_announce_device_401_error(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=401)
    with pytest.raises(XQException) as exc_info:
        announce_device(mock_xqapi, afirst="TestDevice")
    assert "The provided API Key is not valid" in str(exc_info.value)


def test_announce_device_other_error(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=500)
    with pytest.raises(XQException) as exc_info:
        announce_device(mock_xqapi, afirst="TestDevice")
    assert "Failed to verify API key" in str(exc_info.value)
    assert "500" in str(exc_info.value)


def test_exchange_for_dashboard_token_success(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(200, "mock_dashboard_token_123"))
    mock_xqapi.set_dashboard_auth_token = MagicMock()
    mock_xqapi.headers = {"authorization": "Bearer original_token"}
    
    result = exchange_for_dashboard_token(mock_xqapi)
    
    assert result == "mock_dashboard_token_123"
    mock_xqapi.set_dashboard_auth_token.assert_called_once_with("mock_dashboard_token_123")
    mock_xqapi.api_get.assert_called_once_with(
        "login/verify",
        subdomain=API_SUBDOMAIN,
        params={"request": "sub"}
    )


def test_exchange_for_dashboard_token_error(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(401, "Unauthorized"))
    mock_xqapi.headers = {"authorization": "Bearer original_token"}
    
    with pytest.raises(XQException) as exc_info:
        exchange_for_dashboard_token(mock_xqapi)
    assert "Error exchanging for Dashboard token" in str(exc_info.value)


def test_exchange_for_dashboard_token_preserves_original_auth(mock_xqapi):
    """Test that original authorization header is restored after exchange attempt"""
    original_auth = "Bearer original_token"
    mock_xqapi.api_get = MagicMock(return_value=(500, "Server error"))
    mock_xqapi.headers = {"authorization": original_auth}
    
    try:
        exchange_for_dashboard_token(mock_xqapi)
    except XQException:
        pass
    
    # Verify original auth is restored even on error
    assert mock_xqapi.headers["authorization"] == original_auth


def test_get_business_info_success(mock_xqapi):
    mock_response = {
        "id": "business_123",
        "name": "Test Business",
        "email": "business@example.com"
    }
    mock_xqapi.api_get = MagicMock(return_value=(200, mock_response))
    
    result = get_business_info(mock_xqapi)
    
    assert result == mock_response
    mock_xqapi.api_get.assert_called_once_with("business", subdomain=API_SUBDOMAIN)


def test_get_business_info_error_unauthorized(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(401, "Unauthorized"))
    
    with pytest.raises(XQException) as exc_info:
        get_business_info(mock_xqapi)
    assert "Error retrieving business information" in str(exc_info.value)


def test_get_business_info_error_not_found(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(404, "Not Found"))
    
    with pytest.raises(XQException) as exc_info:
        get_business_info(mock_xqapi)
    assert "Error retrieving business information" in str(exc_info.value)


def test_get_business_info_error_server(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(500, "Internal Server Error"))
    
    with pytest.raises(XQException) as exc_info:
        get_business_info(mock_xqapi)
    assert "Error retrieving business information" in str(exc_info.value)


def test_get_businesses_success(mock_xqapi):
    mock_response = [
        {"id": "business_1", "name": "Business One", "role": "owner"},
        {"id": "business_2", "name": "Business Two", "role": "admin"},
        {"id": "business_3", "name": "Business Three", "role": "member"}
    ]
    mock_xqapi.api_get = MagicMock(return_value=(200, mock_response))
    
    result = get_businesses(mock_xqapi)
    
    assert result == mock_response
    assert len(result) == 3
    mock_xqapi.api_get.assert_called_once_with("businesses", subdomain=API_SUBDOMAIN)


def test_get_businesses_empty_list(mock_xqapi):
    """Test when user has no businesses"""
    mock_xqapi.api_get = MagicMock(return_value=(200, []))
    
    result = get_businesses(mock_xqapi)
    
    assert result == []


def test_get_businesses_error_unauthorized(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(401, "Unauthorized"))
    
    with pytest.raises(XQException) as exc_info:
        get_businesses(mock_xqapi)
    assert "Error retrieving businesses" in str(exc_info.value)


def test_get_businesses_error_server(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(500, "Internal Server Error"))
    
    with pytest.raises(XQException) as exc_info:
        get_businesses(mock_xqapi)
    assert "Error retrieving businesses" in str(exc_info.value)


def test_switch_business_success(mock_xqapi):
    new_token = "new_business_token_xyz789"
    mock_xqapi.api_get = MagicMock(return_value=(200, new_token))
    mock_xqapi.set_dashboard_auth_token = MagicMock()
    
    result = switch_business(mock_xqapi, "business_123")
    
    assert result == new_token
    mock_xqapi.api_get.assert_called_once_with(
        "business/business_123/auth", 
        subdomain=API_SUBDOMAIN
    )
    mock_xqapi.set_dashboard_auth_token.assert_called_once_with(new_token)


def test_switch_business_different_ids(mock_xqapi):
    """Test switching to different business IDs"""
    mock_xqapi.api_get = MagicMock(return_value=(200, "token_abc"))
    mock_xqapi.set_dashboard_auth_token = MagicMock()
    
    switch_business(mock_xqapi, "12345")
    assert "business/12345/auth" in mock_xqapi.api_get.call_args[0][0]

def test_switch_business_error_not_found(mock_xqapi):
    """Test switching to non-existent business"""
    mock_xqapi.api_get = MagicMock(return_value=(404, "Business not found"))
    
    with pytest.raises(XQException) as exc_info:
        switch_business(mock_xqapi, "nonexistent_business")
    assert "Error switching business context" in str(exc_info.value)


def test_switch_business_error_forbidden(mock_xqapi):
    """Test switching to business without permission"""
    mock_xqapi.api_get = MagicMock(return_value=(403, "Forbidden"))
    
    with pytest.raises(XQException) as exc_info:
        switch_business(mock_xqapi, "unauthorized_business")
    assert "Error switching business context" in str(exc_info.value)


def test_switch_business_error_unauthorized(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(401, "Unauthorized"))
    
    with pytest.raises(XQException) as exc_info:
        switch_business(mock_xqapi, "123")
    assert "Error switching business context" in str(exc_info.value)


def test_switch_business_error_server(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(500, "Internal Server Error"))
    
    with pytest.raises(XQException) as exc_info:
        switch_business(mock_xqapi, "b123")
    assert "Error switching business context" in str(exc_info.value)