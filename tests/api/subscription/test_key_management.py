import pytest
from unittest.mock import MagicMock

from xq.api.subscription.key_management import *


def test_create_packet_200(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(200, "mock server success"))
    assert create_packet(
        mock_xqapi, recipients="mock@test.com", key=b"justasupersecret"
    )


def test_create_packet_error(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        create_packet(mock_xqapi, recipients="mock@test.com", key=b"justasupersecret")


def test_create_packets_200(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(200, "mock server success"))
    assert create_and_store_packet(
        mock_xqapi, recipients="mock@test.com", key=b"justasupersecret"
    )


def test_create_packets_error(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        create_and_store_packet(
            mock_xqapi, recipients="mock@test.com", key=b"justasupersecret"
        )
