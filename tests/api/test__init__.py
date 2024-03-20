import pytest
from requests import Session
from unittest.mock import MagicMock, patch
import os

from xq.api import XQAPI
from xq.exceptions import SDKConfigurationException


@patch.object(Session, "get")
def test_api_get_text(mock_get, mock_xqapi):
    mockres = "mock server success"
    mock_get.return_value.status_code.return_value = 200
    mock_get.return_value.json.side_effect = MagicMock(
        side_effect=Exception("Method not found")
    )  # force mock to throw error
    mock_get.return_value.text = mockres

    res = mock_xqapi.api_get("mockEndpoint", "mockSubdomain", params={})
    assert res[1] == mockres


@patch.object(Session, "get")
def test_api_get_json(mock_get, mock_xqapi):
    mockres = {"mock": "server sucess"}
    mock_get.return_value.status_code.return_value = 200
    mock_get.return_value.json.return_value = mockres

    res = mock_xqapi.api_get("mockEndpoint", "mockSubdomain", params={})
    assert res[1] == mockres


@patch.object(Session, "post")
def test_api_post_text(mock_post, mock_xqapi):
    mockres = "mock server success"
    mock_post.return_value.status_code.return_value = 200
    mock_post.return_value.json.side_effect = MagicMock(
        side_effect=Exception("Method not found")
    )  # force mock to throw error
    mock_post.return_value.text = mockres

    res = mock_xqapi.api_post("mockEndpoint", "mockSubdomain", data=mockres)
    assert res[1] == mockres


@patch.object(Session, "post")
def test_api_post_json(mock_post, mock_xqapi):
    mockres = {"mock": "server sucess"}
    mock_post.return_value.status_code.return_value = 200
    mock_post.return_value.json.return_value = mockres

    res = mock_xqapi.api_post("mockEndpoint", "mockSubdomain", json=mockres)
    assert res[1] == mockres


@patch.object(Session, "delete")
def test_api_delete_text(mock_delete, mock_xqapi):
    mockres = "mock server success"
    mock_delete.return_value.status_code.return_value = 200
    mock_delete.return_value.json.side_effect = MagicMock(
        side_effect=Exception("Method not found")
    )  # force mock to throw error
    mock_delete.return_value.text = mockres

    res = mock_xqapi.api_delete("mockEndpoint", "mockSubdomain")
    assert res[1] == mockres


@patch.object(Session, "delete")
def test_api_delete_json(mock_delete, mock_xqapi):
    mockres = {"mock": "server sucess"}
    mock_delete.return_value.status_code.return_value = 200
    mock_delete.return_value.json.return_value = mockres

    res = mock_xqapi.api_delete("mockEndpoint", "mockSubdomain")
    assert res[1] == mockres


@patch.object(Session, "patch")
def test_api_patch_text(mock_patch, mock_xqapi):
    mockres = "mock server success"
    mock_patch.return_value.status_code.return_value = 200
    mock_patch.return_value.json.side_effect = MagicMock(
        side_effect=Exception("Method not found")
    )  # force mock to throw error
    mock_patch.return_value.text = mockres

    res = mock_xqapi.api_patch("mockEndpoint", "mockSubdomain", data=mockres)
    assert res[1] == mockres


@patch.object(Session, "patch")
def test_api_patch_json(mock_patch, mock_xqapi):
    mockres = {"mock": "server sucess"}
    mock_patch.return_value.status_code.return_value = 200
    mock_patch.return_value.json.return_value = mockres

    res = mock_xqapi.api_patch("mockEndpoint", "mockSubdomain", json=mockres)
    assert res[1] == mockres
