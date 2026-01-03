import pytest
from unittest.mock import MagicMock

from xq.api.subscription.key_management import *




def test_create_and_store_packet_200(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(200, "mock server success"))
    assert create_and_store_packet(
        mock_xqapi, recipients="mock@test.com", key=b"justasupersecret"
    )


def test_create_and_store_packet_error(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        create_and_store_packet(
            mock_xqapi, recipients=["mock@test.com"], key=b"justasupersecret"
        )

def test_create_and_store_packets_200(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(200, "mock server success"))
    assert create_and_store_packets(
        mock_xqapi, recipients=["mock@test.com"], keys=[b"justasupersecret", b"justasupersecret2"]
    )


def test_create_and_store_packets_error(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        create_and_store_packets(
            mock_xqapi, recipients=["mock@test.com"], keys=[b"justasupersecret", b"justasupersecret2"]
        )
def test_create_and_store_packets_batch_200(mock_xqapi):
    metadata = [
        {"title": "test 1", "labels": ["cui", "secret", "production"]},
        {"title": "test 2", "labels": ["team", "contact", "staging"]}
    ]
    mock_xqapi.api_post = MagicMock(return_value=(200, "mock server success"))
    assert create_and_store_packets_batch(
        mock_xqapi, recipients=["mock@test.com"], metadata_list=metadata, keys=[b"justasupersecret", b"justasupersecret2"]
    )


def test_create_and_store_packets_batch_error(mock_xqapi):
    metadata = [
        {"title": "test 1", "labels": ["cui", "secret", "production"]},
        {"title": "test 2", "labels": ["team", "contact", "staging"]},
    ]
    mock_xqapi.api_post = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        create_and_store_packets_batch(
            mock_xqapi, recipients=["mock@test.com"], metadata_list=metadata, keys=[b"justasupersecret", b"justasupersecret2"]
        )
