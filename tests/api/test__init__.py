import pytest
from unittest.mock import MagicMock, patch
import os

from xq.api import XQAPI
from xq.exceptions import SDKConfigurationException


@patch("xq.api.requests")
def test_api_get_text(mock_requests, mock_xqapi):
    mockres = "mock server success"
    mock_requests.get.return_value.status_code.return_value = 200
    mock_requests.get.return_value.json.side_effect = MagicMock(
        side_effect=Exception("Method not found")
    )  # force mock to throw error
    mock_requests.get.return_value.text = mockres

    res = mock_xqapi.api_get("mockEndpoint", "mockSubdomain", params={})
    assert res[1] == mockres


@patch("xq.api.requests")
def test_api_get_json(mock_requests, mock_xqapi):
    mockres = {"mock": "server sucess"}
    mock_requests.get.return_value.status_code.return_value = 200
    mock_requests.get.return_value.json.return_value = mockres

    res = mock_xqapi.api_get("mockEndpoint", "mockSubdomain", params={})
    assert res[1] == mockres


@patch("xq.api.requests")
def test_api_post_text(mock_requests, mock_xqapi):
    mockres = "mock server success"
    mock_requests.post.return_value.status_code.return_value = 200
    mock_requests.post.return_value.json.side_effect = MagicMock(
        side_effect=Exception("Method not found")
    )  # force mock to throw error
    mock_requests.post.return_value.text = mockres

    res = mock_xqapi.api_post("mockEndpoint", "mockSubdomain", data=mockres)
    assert res[1] == mockres


@patch("xq.api.requests")
def test_api_post_json(mock_requests, mock_xqapi):
    mockres = {"mock": "server sucess"}
    mock_requests.post.return_value.status_code.return_value = 200
    mock_requests.post.return_value.json.return_value = mockres

    res = mock_xqapi.api_post("mockEndpoint", "mockSubdomain", json=mockres)
    assert res[1] == mockres


@patch("xq.api.requests")
def test_api_delete_text(mock_requests, mock_xqapi):
    mockres = "mock server success"
    mock_requests.delete.return_value.status_code.return_value = 200
    mock_requests.delete.return_value.json.side_effect = MagicMock(
        side_effect=Exception("Method not found")
    )  # force mock to throw error
    mock_requests.delete.return_value.text = mockres

    res = mock_xqapi.api_delete("mockEndpoint", "mockSubdomain")
    assert res[1] == mockres


@patch("xq.api.requests")
def test_api_delete_json(mock_requests, mock_xqapi):
    mockres = {"mock": "server sucess"}
    mock_requests.delete.return_value.status_code.return_value = 200
    mock_requests.delete.return_value.json.return_value = mockres

    res = mock_xqapi.api_delete("mockEndpoint", "mockSubdomain")
    assert res[1] == mockres


@patch("xq.api.requests")
def test_api_patch_text(mock_requests, mock_xqapi):
    mockres = "mock server success"
    mock_requests.patch.return_value.status_code.return_value = 200
    mock_requests.patch.return_value.json.side_effect = MagicMock(
        side_effect=Exception("Method not found")
    )  # force mock to throw error
    mock_requests.patch.return_value.text = mockres

    res = mock_xqapi.api_patch("mockEndpoint", "mockSubdomain", data=mockres)
    assert res[1] == mockres


@patch("xq.api.requests")
def test_api_patch_json(mock_requests, mock_xqapi):
    mockres = {"mock": "server sucess"}
    mock_requests.patch.return_value.status_code.return_value = 200
    mock_requests.patch.return_value.json.return_value = mockres

    res = mock_xqapi.api_patch("mockEndpoint", "mockSubdomain", json=mockres)
    assert res[1] == mockres
