import pytest
from unittest.mock import MagicMock

from xq.api.validation.key_management import *


def test_get_packet_200(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(200, "mock server success"))
    assert get_packet(mock_xqapi, "mocklocatortoken")


def test_get_packet_error(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        get_packet(mock_xqapi, "mocklocatortoken")


def test_get_packets_200(mock_xqapi):
     mock_xqapi.api_post = MagicMock(return_value=(200, "mock server success"))
     assert get_packets(mock_xqapi, "mocklocatortoken")


def test_get_packets_error(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
         get_packets(mock_xqapi, "mocklocatortoken")


def test_revoke_packet_200(mock_xqapi):
    mock_xqapi.api_delete = MagicMock(return_value=(200, "mock server success"))
    assert revoke_packet(mock_xqapi, "mocklocatortoken")


def test_revoke_packet_error(mock_xqapi):
    mock_xqapi.api_delete = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        revoke_packet(mock_xqapi, "mocklocatortoken")


def test_grant_users_200(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(201, "mock server success"))
    assert grant_users(mock_xqapi, "mocklocatortoken", ["mockrecipient@xqtest.com"])


def test_grant_users_error(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        grant_users(mock_xqapi, "mocklocatortoken", ["mockrecipient@xqtest.com"])


def test_revoke_users_200(mock_xqapi):
    mock_xqapi.api_delete = MagicMock(return_value=(204, "mock server success"))
    assert revoke_users(mock_xqapi, "mocklocatortoken", ["mockrecipient@xqtest.com"])


def test_revoke_users_error(mock_xqapi):
    mock_xqapi.api_delete = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        revoke_users(mock_xqapi, "mocklocatortoken", ["mockrecipient@xqtest.com"])

def test_grant_users_alias_access_200(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(201, "mock server success"))

    result = grant_users(
        mock_xqapi,
        "mocklocatortoken",
        ["user@example.com"],
        alias_access=True,
    )

    assert result is True
    mock_xqapi.api_post.assert_called_once()
    args, kwargs = mock_xqapi.api_post.call_args

    assert kwargs["json"] == {
        "recipients": ["user@example.com@alias.local"]
    }


def test_revoke_users_alias_access_200(mock_xqapi):
    mock_xqapi.api_delete = MagicMock(return_value=(204, "mock server success"))

    result = revoke_users(
        mock_xqapi,
        "mocklocatortoken",
        ["user@example.com"],
        alias_access=True,
    )

    assert result is True
    mock_xqapi.api_delete.assert_called_once()
    args, kwargs = mock_xqapi.api_delete.call_args

    assert kwargs["json"] == {
        "recipients": ["user@example.com@alias.local"]
    }
