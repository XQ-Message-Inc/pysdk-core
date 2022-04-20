import pytest
from unittest.mock import MagicMock

from xq.api.manage.authentication import *
from xq.exceptions import XQException


def test_dashboard_login_oauth(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(200, "mock server success"))
    dashboard_login(mock_xqapi)


def test_dashboard_login_creds(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(200, "mock server success"))
    dashboard_login(mock_xqapi, email="mocker@xqtest.com", password="mockpass")


def test_dashboard_login_creds_missing(mock_xqapi):
    with pytest.raises(XQException):
        dashboard_login(mock_xqapi, method=0)


def test_dashboard_login_error(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        dashboard_login(mock_xqapi)
