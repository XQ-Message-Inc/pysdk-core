import pytest
from unittest.mock import MagicMock

from xq.api.manage.usergroup import *
from xq.exceptions import XQException


def test_create_usergroup(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(200, "mock server success"))
    assert create_usergroup(mock_xqapi, name="mockname", members=["mockmember"])


def test_create_usergroup_success(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(200, {"id": 1, "name": "test", "members": ["a@example.com"]}))
    result = create_usergroup(mock_xqapi, name="test", members=["a@example.com"])
    assert result["name"] == "test"
    assert "a@example.com" in result["members"]

def test_create_usergroup_error(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(500, "error"))
    with pytest.raises(XQException):
        create_usergroup(mock_xqapi, name="fail", members=["fail@example.com"])


def test_get_usergroup(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(200, "mock server success"))
    assert get_usergroup(mock_xqapi)


def test_get_usergroup_by_id(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(200, {"id": 1, "name": "test"}))
    result = get_usergroup(mock_xqapi, usergroup_id=1)
    assert result["id"] == 1


def test_get_usergroup_by_name(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(200, {"groups": [{"id": 2, "name": "foo"}, {"id": 3, "name": "bar"}]}))
    result = get_usergroup(mock_xqapi, name="foo")
    assert result["name"] == "foo"


def test_get_usergroup_all(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(200, {"groups": [{"id": 1}, {"id": 2}]}))
    result = get_usergroup(mock_xqapi)
    assert isinstance(result, dict)
    assert "groups" in result

def test_update_usergroup(mock_xqapi):
    mock_xqapi.api_patch = MagicMock(return_value=(204, "mock server success"))
    assert update_usergroup(mock_xqapi, 1, "mockname", "mockmemebers")


def test_update_usergroup_success(mock_xqapi):
    mock_xqapi.api_patch = MagicMock(return_value=(204, {"id": 1, "name": "updated"}))
    result = update_usergroup(mock_xqapi, 1, "updated", ["a@example.com"])
    assert result["name"] == "updated"


def test_update_usergroup_error(mock_xqapi):
    mock_xqapi.api_patch = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        update_usergroup(mock_xqapi, 1, "fail", ["fail@example.com"])


def test_delete_usergroup(mock_xqapi):
    mock_xqapi.api_delete = MagicMock(return_value=(204, "mock server success"))
    assert delete_usergroup(mock_xqapi, 1)


def test_delete_usergroup_success(mock_xqapi):
    mock_xqapi.api_delete = MagicMock(return_value=(204, "ok"))
    assert delete_usergroup(mock_xqapi, 1) is True


def test_delete_usergroup_error(mock_xqapi):
    mock_xqapi.api_delete = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        delete_usergroup(mock_xqapi, 1)


def test_add_usergroup_members(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(200, {"name": "testgroup", "members": [
        {"kind": "address", "address": "existing@example.com"}
    ]}))
    mock_xqapi.api_patch = MagicMock(return_value=(204, {"id": 1, "name": "testgroup"}))
    result = add_usergroup_members(mock_xqapi, usergroup_id=1, members="new@example.com")
    call_args = mock_xqapi.api_patch.call_args
    assert "new@example.com" in call_args[1]["json"]["members"]
    assert "existing@example.com" in call_args[1]["json"]["members"]


def test_remove_usergroup_members(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(200, {"name": "testgroup", "members": [
        {"kind": "address", "address": "keep@example.com"},
        {"kind": "address", "address": "remove@example.com"}
    ]}))
    mock_xqapi.api_patch = MagicMock(return_value=(204, {"id": 1, "name": "testgroup"}))
    result = remove_usergroup_members(mock_xqapi, usergroup_id=1, members="remove@example.com")
    call_args = mock_xqapi.api_patch.call_args
    assert "keep@example.com" in call_args[1]["json"]["members"]
    assert "remove@example.com" not in call_args[1]["json"]["members"]
