import pytest
from unittest.mock import MagicMock

from xq.api.manage.communications import *
from xq.exceptions import XQException


def test_get_communications_by_locator(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(200, "mock server success"))
    get_communication_by_locator_token(
        mock_xqapi, "Mock"
    )