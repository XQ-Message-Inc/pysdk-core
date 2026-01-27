from sys import exc_info
import pytest
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