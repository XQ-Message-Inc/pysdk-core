import pytest
from unittest.mock import MagicMock

from xq.api.manage.usergroup import *
from xq.exceptions import XQException


def test_create_usergroup(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(200, "mock server success"))
    assert create_usergroup(mock_xqapi, name="mockname", members=["mockmember"])


def test_create_usergroup_error(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        create_usergroup(mock_xqapi, name="mockname", members=["mockmember"])


def test_get_usergroup(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(200, "mock server success"))
    assert get_usergroup(mock_xqapi)


def test_get_usergroup(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        get_usergroup(mock_xqapi)


def test_update_usergroup(mock_xqapi):
    mock_xqapi.api_patch = MagicMock(return_value=(204, "mock server success"))
    assert update_usergroup(mock_xqapi, 1, "mockname", "mockmemebers")


def test_update_usergroup_error(mock_xqapi):
    mock_xqapi.api_patch = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        update_usergroup(mock_xqapi, 1, "mockname", "mockmemebers")


def test_delete_usergroup(mock_xqapi):
    mock_xqapi.api_delete = MagicMock(return_value=(204, "mock server success"))
    assert delete_usergroup(mock_xqapi, 1)


def test_delete_usergroup_error(mock_xqapi):
    mock_xqapi.api_delete = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        delete_usergroup(mock_xqapi, 1)
