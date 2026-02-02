import pytest
from unittest.mock import MagicMock

from xq.api.quantum.generator import *


def test_get_entropy_200(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(200, {"data":"MQ=="}))  # returns base64 string
    assert get_entropy(mock_xqapi)


def test_get_entropy_error(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        get_entropy(mock_xqapi)
