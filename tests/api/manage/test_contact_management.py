import pytest
from unittest.mock import MagicMock

from xq.api.manage.contact_management import *
from xq.exceptions import XQException


def test_add_team_member_200(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(200, "mock server success"))
    res = add_team_member(
        mock_xqapi, "Mock", "Mocker", "mocker@xqtest.com", "Chief Mocker Officer", "User"
    )
    assert res


def test_add_team_member_error(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        add_team_member(
            mock_xqapi, "Mock", "Mocker", "mocker@xqtest.com", "Chief Mocker Officer", "InvalidRole"
        )

def test_add_team_member_invalid_params(mock_xqapi):
    with pytest.raises(TypeError):
        add_team_member(mock_xqapi)

def test_delete_team_member_200(mock_xqapi):
    mock_xqapi.api_delete = MagicMock(return_value=(204, "mock server success"))
    res = delete_team_member(mock_xqapi, 1)
    assert res


def test_delete_team_member_error(mock_xqapi):
    mock_xqapi.api_delete = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        delete_team_member(mock_xqapi, 1)
