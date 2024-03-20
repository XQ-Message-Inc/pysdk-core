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


def test_add_packet_200(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(200, "mock server success"))
    assert add_packet(mock_xqapi, "mocklocatortoken")


def test_add_packet_error(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        add_packet(mock_xqapi, "mocklocatortoken")


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
    mock_xqapi.api_patch = MagicMock(return_value=(204, "mock server success"))
    assert revoke_users(mock_xqapi, "mocklocatortoken", ["mockrecipient@xqtest.com"])


def test_revoke_users_error(mock_xqapi):
    mock_xqapi.api_patch = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        revoke_users(mock_xqapi, "mocklocatortoken", ["mockrecipient@xqtest.com"])
