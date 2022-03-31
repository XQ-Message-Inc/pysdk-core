from unittest import mock
import pytest
from unittest.mock import patch, MagicMock

from xq.api import XQAPI


@pytest.fixture
def mock_xqapi():
    # override checking for valid provided keys
    with patch.object(XQAPI, "validate_api_key", return_value=(200, "api is good")):
        xqapi = XQAPI()
        yield xqapi
