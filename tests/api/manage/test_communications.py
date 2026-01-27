import pytest
from unittest.mock import MagicMock
import urllib.parse

from xq.api.manage.communications import *
from xq.exceptions import XQException


def test_get_communications_by_locator(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(200, "mock server success"))
    get_communication_by_locator_token(
        mock_xqapi, "Mock"
    )


def test_get_communication_by_locator_token_success(mock_xqapi):
    mock_response = {
        "id": "comm_123",
        "locator_token": "test_token_abc123",
        "labels": ["label1", "label2"]
    }
    mock_xqapi.api_get = MagicMock(return_value=(200, mock_response))
    
    result = get_communication_by_locator_token(mock_xqapi, "test_token_abc123")
    
    assert result == mock_response
    mock_xqapi.api_get.assert_called_once_with(
        f"communication/{urllib.parse.quote_plus('test_token_abc123')}", 
        subdomain=API_SUBDOMAIN
    )


def test_get_communication_by_locator_token_with_special_chars(mock_xqapi):
    """Test URL encoding of locator tokens with special characters"""
    mock_xqapi.api_get = MagicMock(return_value=(200, {"id": "comm_123"}))
    token_with_special_chars = "token/with+special=chars"
    
    get_communication_by_locator_token(mock_xqapi, token_with_special_chars)
    
    # Verify token was URL encoded
    mock_xqapi.api_get.assert_called_once_with(
        f"communication/{urllib.parse.quote_plus(token_with_special_chars)}", 
        subdomain=API_SUBDOMAIN
    )


def test_get_communication_by_locator_token_error_404(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(404, "Not Found"))
    
    with pytest.raises(XQException) as exc_info:
        get_communication_by_locator_token(mock_xqapi, "nonexistent_token")
    assert "Communication retrieval failed" in str(exc_info.value)


def test_get_communication_by_locator_token_error_401(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(401, "Unauthorized"))
    
    with pytest.raises(XQException) as exc_info:
        get_communication_by_locator_token(mock_xqapi, "test_token")
    assert "Communication retrieval failed" in str(exc_info.value)


def test_add_labels_to_locator_token_success_200(mock_xqapi):
    mock_response = {"success": True}
    mock_xqapi.api_patch = MagicMock(return_value=(200, mock_response))
    labels = ["important", "customer-data"]
    
    result = add_labels_to_locator_token(mock_xqapi, "test_token", labels)
    
    assert result == mock_response
    mock_xqapi.api_patch.assert_called_once_with(
        f"communication/{urllib.parse.quote_plus('test_token')}/labels",
        json={"labels": labels},
        subdomain=API_SUBDOMAIN
    )


def test_add_labels_to_locator_token_success_204(mock_xqapi):
    mock_xqapi.api_patch = MagicMock(return_value=(204, ""))
    labels = ["archived"]
    
    result = add_labels_to_locator_token(mock_xqapi, "test_token", labels)
    
    assert result == ""


def test_add_labels_to_locator_token_empty_labels(mock_xqapi):
    """Test adding empty labels list"""
    mock_xqapi.api_patch = MagicMock(return_value=(200, {"success": True}))
    
    result = add_labels_to_locator_token(mock_xqapi, "test_token", [])
    
    assert result == {"success": True}
    # Verify empty list was sent in payload
    call_args = mock_xqapi.api_patch.call_args
    assert call_args[1]["json"]["labels"] == []


def test_add_labels_to_locator_token_multiple_labels(mock_xqapi):
    """Test adding multiple labels"""
    mock_xqapi.api_patch = MagicMock(return_value=(200, {"success": True}))
    labels = ["urgent", "reviewed", "finance", "Q1-2026"]
    
    add_labels_to_locator_token(mock_xqapi, "test_token", labels)
    
    call_args = mock_xqapi.api_patch.call_args
    assert call_args[1]["json"]["labels"] == labels


def test_add_labels_to_locator_token_with_special_char_token(mock_xqapi):
    """Test URL encoding when adding labels to token with special characters"""
    mock_xqapi.api_patch = MagicMock(return_value=(200, {"success": True}))
    token_with_special_chars = "token/with+chars"
    
    add_labels_to_locator_token(mock_xqapi, token_with_special_chars, ["label1"])
    
    # Verify token was URL encoded in the path
    mock_xqapi.api_patch.assert_called_once_with(
        f"communication/{urllib.parse.quote_plus(token_with_special_chars)}/labels",
        json={"labels": ["label1"]},
        subdomain=API_SUBDOMAIN
    )


def test_add_labels_to_locator_token_error_400(mock_xqapi):
    mock_xqapi.api_patch = MagicMock(return_value=(400, "Bad Request"))
    
    with pytest.raises(XQException) as exc_info:
        add_labels_to_locator_token(mock_xqapi, "test_token", ["invalid"])
    assert "Adding labels failed" in str(exc_info.value)


def test_add_labels_to_locator_token_error_401(mock_xqapi):
    mock_xqapi.api_patch = MagicMock(return_value=(401, "Unauthorized"))
    
    with pytest.raises(XQException) as exc_info:
        add_labels_to_locator_token(mock_xqapi, "test_token", ["label"])
    assert "Adding labels failed" in str(exc_info.value)


def test_add_labels_to_locator_token_error_404(mock_xqapi):
    mock_xqapi.api_patch = MagicMock(return_value=(404, "Communication not found"))
    
    with pytest.raises(XQException) as exc_info:
        add_labels_to_locator_token(mock_xqapi, "nonexistent_token", ["label"])
    assert "Adding labels failed" in str(exc_info.value)


def test_add_labels_to_locator_token_error_500(mock_xqapi):
    mock_xqapi.api_patch = MagicMock(return_value=(500, "Internal Server Error"))
    
    with pytest.raises(XQException) as exc_info:
        add_labels_to_locator_token(mock_xqapi, "test_token", ["label"])
    assert "Adding labels failed" in str(exc_info.value)