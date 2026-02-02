from sys import exc_info
import pytest
from unittest.mock import MagicMock
import tempfile
import os

from xq.api.manage.authentication import *
from xq.exceptions import XQException

def test_send_login_link(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(200, {"code": ""}))
    assert send_login_link(mock_xqapi, email="mockuser@xqtest.com")


def test_send_login_link_error(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        send_login_link(mock_xqapi, email="mockuser@xqtest.com")


def test_login_verify(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(204, "mock server success"))
    mock_xqapi.headers["code"] = "code"
    login_verify(mock_xqapi, 1)


def test_login_verify_error(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(500, "mock server error"))
    mock_xqapi.headers["code"] = "code"
    with pytest.raises(XQException):
        login_verify(mock_xqapi, 1)


def test_validate_access_token(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(204, "mock server success"))
    validate_access_token(mock_xqapi)


def test_validate_access_token_error(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        validate_access_token(mock_xqapi)

def test_create_certificate_success(mock_xqapi):
    """Test successful device certificate generation without file output"""
    mock_response = {
        "id": 123,
        "transportKey": "dHJhbnNwb3J0S2V5QmFzZTY0RW5jb2RlZA==",
        "clientCert": "Y2xpZW50Q2VydEJhc2U2NEVuY29kZWQ=",
        "clientKey": "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCm1vY2tfa2V5X2Jhc2U2NAotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0t"
    }
    mock_xqapi.api_post = MagicMock(return_value=(200, mock_response))

    result = create_certificate(mock_xqapi, tag="test_device")

    assert result == mock_response
    assert result["id"] == 123
    assert result["transportKey"] == "dHJhbnNwb3J0S2V5QmFzZTY0RW5jb2RlZA=="
    assert result["clientCert"] == "Y2xpZW50Q2VydEJhc2U2NEVuY29kZWQ="
    mock_xqapi.api_post.assert_called_once()
    call_args = mock_xqapi.api_post.call_args
    assert call_args[1]["json"]["tag"] == "test_device"
    assert call_args[1]["json"]["enabled"] is True
    assert call_args[1]["json"]["geofence"] == []


def test_create_certificate_with_fence(mock_xqapi):
    """Test device certificate generation with fence parameter"""
    mock_response = {
        "id": 456,
        "transportKey": "dHJhbnNwb3J0X2tleV9iYXNlNjQ=",
        "clientCert": "Y2xpZW50X2NlcnRfYmFzZTY0",
        "clientKey": "Y2xpZW50X2tleV9iYXNlNjQ="
    }
    mock_xqapi.api_post = MagicMock(return_value=(200, mock_response))

    fence = ["scope1", "scope2"]
    result = create_certificate(
        mock_xqapi,
        tag="fenced_device",
        fence=fence,
        enabled=False
    )

    assert result == mock_response
    call_args = mock_xqapi.api_post.call_args
    assert call_args[1]["json"]["geofence"] == fence
    assert call_args[1]["json"]["enabled"] is False


def test_create_certificate__with_output_dir(mock_xqapi):
    """Test device certificate generation with file output to directory"""
    mock_response = {
        "id": 789,
        "transportKey": "dHJhbnNwb3J0X2NvbnRlbnRfYmFzZTY0",
        "clientCert": "Y2VydF9jb250ZW50X2Jhc2U2NA==",
        "clientKey": "a2V5X2NvbnRlbnRfYmFzZTY0"
    }
    mock_xqapi.api_post = MagicMock(return_value=(200, mock_response))

    with tempfile.TemporaryDirectory() as tmpdir:
        result = create_certificate(
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


def test_create_certificate__with_custom_paths(mock_xqapi):
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

        result = create_certificate(
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


def test_create_certificate__output_dir_creates_directory(mock_xqapi):
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

        create_certificate(
            mock_xqapi,
            tag="mkdir_device",
            output_dir=new_dir
        )

        # Check directory was created
        assert os.path.exists(new_dir)
        assert os.path.exists(os.path.join(new_dir, "client.key"))


def test_create_certificate__error_response(mock_xqapi):
    """Test error handling when API returns non-200 status"""
    mock_xqapi.api_post = MagicMock(return_value=(403, "Forbidden"))

    with pytest.raises(XQException) as exc_info:
        create_certificate(mock_xqapi, tag="error_device")
    assert "Failed creating certificate" in str(exc_info.value)


def test_create_certificate__missing_required_param(mock_xqapi):
    """Test that tag parameter is required"""
    with pytest.raises(TypeError):
        create_certificate(mock_xqapi)

def test_get_team_error_unauthorized(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(401, "Unauthorized"))

    with pytest.raises(XQException) as exc_info:
        get_team(mock_xqapi)
    assert "Error retrieving business information" in str(exc_info.value)


def test_get_team_error_not_found(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(404, "Not Found"))

    with pytest.raises(XQException) as exc_info:
        get_team(mock_xqapi)
    assert "Error retrieving business information" in str(exc_info.value)


def test_get_team_error_server(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(500, "Internal Server Error"))

    with pytest.raises(XQException) as exc_info:
        get_team(mock_xqapi)
    assert "Error retrieving business information" in str(exc_info.value)


def test_get_registered_teams_success(mock_xqapi):
    mock_response = [
        {"id": "business_1", "name": "Business One", "role": "owner"},
        {"id": "business_2", "name": "Business Two", "role": "admin"},
        {"id": "business_3", "name": "Business Three", "role": "member"}
    ]
    mock_xqapi.api_get = MagicMock(return_value=(200, mock_response))

    result = get_registered_teams(mock_xqapi)

    assert result == mock_response
    assert len(result) == 3
    mock_xqapi.api_get.assert_called_once_with("registered", subdomain=API_SUBDOMAIN)


def test_get_registered_teams_empty_list(mock_xqapi):
    """Test when user has no businesses"""
    mock_xqapi.api_get = MagicMock(return_value=(200, []))

    result = get_registered_teams(mock_xqapi)

    assert result == []


def test_get_registered_teams_error_unauthorized(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(401, "Unauthorized"))

    with pytest.raises(XQException) as exc_info:
        get_registered_teams(mock_xqapi)
    assert "Error retrieving businesses" in str(exc_info.value)


def test_get_registered_teams_error_server(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(500, "Internal Server Error"))

    with pytest.raises(XQException) as exc_info:
        get_registered_teams(mock_xqapi)
    assert "Error retrieving businesses" in str(exc_info.value)


