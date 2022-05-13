import pytest
from unittest.mock import MagicMock

from xq.api.manage.contact_management import *
from xq.exceptions import XQException


def test_add_contact(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(200, "mock server success"))
    add_contact(
        mock_xqapi, "Mock", "Mocker", "mocker@xqtest.com", "Chief Mocker Officer", 6
    )


def test_add_contact_error(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        add_contact(
            mock_xqapi, "Mock", "Mocker", "mocker@xqtest.com", "Chief Mocker Officer", 6
        )


def test_add_contact_invalid_params(mock_xqapi):
    with pytest.raises(TypeError):
        add_contact(mock_xqapi)
