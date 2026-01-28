from sys import exc_info
import pytest
from unittest.mock import MagicMock

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
