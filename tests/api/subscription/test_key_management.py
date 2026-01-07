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

def test_create_and_store_packets_200(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(200, {"tokens": ["t1", "t2"]}))

    res = create_and_store_packets(
        mock_xqapi,
        recipients=["user@example.com"],
        expires_hours=12,
        keys=[b"key1-bytes", "key2-str"],
        type="msg",
        subject="Test subject",
        meta="meta-info",
    )

    mock_xqapi.api_post.assert_called_once()
    called_args, called_kwargs = mock_xqapi.api_post.call_args
    assert called_args[0] == "packet/add"
    payload = called_kwargs["json"]
    assert payload["meta"]["subject"] == "Test subject"
    assert payload["meta"]["meta"] == "meta-info"
    # keys should all be strings after decode
    assert payload["keys"] == ["key1-bytes", "key2-str"]
    assert res == {"tokens": ["t1", "t2"]}

def test_create_and_store_packets_error(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(500, "mock server error"))

    with pytest.raises(XQException, match="Packet creation failed"):
        create_and_store_packets(
            mock_xqapi,
            recipients=["user@example.com"],
            keys=[b"key1"],
        )

def test_create_and_store_packets_batch_metadata_mismatch_raises(mock_xqapi):
    with pytest.raises(XQException, match="metadata_list length"):
        create_and_store_packets_batch(
            mock_xqapi,
            keys=[b"k1", b"k2"],
            recipients=["user@example.com"],
            metadata_list=[{"title": "only-one"}],  # length 1 vs 2 keys
        )

def test_create_and_store_packets_batch_200(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(200, {"tokens": ["t1", "t2"]}))

    keys = [b"k1-bytes", "k2-str"]
    metadata_list = [
        {"title": "row-1", "labels": ["a"]},
        {"title": "row-2", "labels": ["b"]},
    ]

    res = create_and_store_packets_batch(
        mock_xqapi,
        keys=keys,
        recipients=["user@example.com"],
        metadata_list=metadata_list,
        expires=7,
        unit="days",
        type="database",
    )

    mock_xqapi.api_post.assert_called_once()
    called_args, called_kwargs = mock_xqapi.api_post.call_args
    assert called_args[0] == "packet/batch"

    payload = called_kwargs["json"]
    entries = payload["entries"]
    assert len(entries) == 2

    assert entries[0]["type"] == "database"
    assert entries[0]["meta"] == metadata_list[0]
    assert entries[0]["key"] == "k1-bytes"
    assert entries[0]["recipients"] == ["user@example.com"]
    assert entries[0]["expires"] == 7
    assert entries[0]["unit"] == "days"

    assert entries[1]["meta"] == metadata_list[1]
    assert entries[1]["key"] == "k2-str"

    assert res == {"tokens": ["t1", "t2"]}

def test_create_and_store_packets_batch_error(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(500, "mock batch error"))

    with pytest.raises(XQException, match="Batch packet creation failed"):
        create_and_store_packets_batch(
            mock_xqapi,
            keys=[b"k1"],
            recipients=["user@example.com"],
        )

def test_create_packet_with_str_key(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(200, "ok"))
    res = create_packet(
        mock_xqapi, recipients=["mock@test.com"], key="already-a-string"
    )
    called_args, called_kwargs = mock_xqapi.api_post.call_args
    payload = called_kwargs["json"]
    assert payload["key"] == "already-a-string"
    assert res == "ok"
