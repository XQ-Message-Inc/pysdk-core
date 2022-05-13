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
