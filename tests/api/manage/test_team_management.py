import pytest
from unittest.mock import MagicMock

from xq.api.manage.team_management import *
from xq.exceptions import XQException


def test_create_team(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(200, {"id": {"xxx": "xxxx"}}))
    assert create_team(mock_xqapi, name="new team")


def test_create_team_error(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        create_team(mock_xqapi,  name="new team")


def test_get_teams(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(200, "mock server success"))
    assert get_teams(mock_xqapi)


def test_get_teams_error(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        get_teams(mock_xqapi)


def test_switch(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(200, {'access_token': 'mock contents'}))
    assert switch(mock_xqapi, 1)


def test_switch_error(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        switch(mock_xqapi, 1)
