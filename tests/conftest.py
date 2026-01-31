from unittest import mock
import pytest
from unittest.mock import patch, MagicMock
import requests
import copy

from xq import XQ
from xq.api import XQAPI


def mock_init(cls, *args, **kwargs):
    # Your custom testing override
    return None


@pytest.fixture
def mock_xqapi():
    # with mock.patch("xq.XQAPI") as mock_api:
    #     mock_api.validate_api_key = MagicMock(
    #         return_value=True
    #     )  # override checking for valid provided keys

    #     yield mock_api()

    with mock.patch.object(XQAPI, "__init__", new=mock_init):
        xqapi = XQAPI()
        xqapi.headers = {}
        xqapi.api_base_uri = "mockbaseuri"
        xqapi.session = requests.session()
        xqapi.api_key = "mock_api_key"
        xqapi.dashboard_api_key = "mock_dashboard_api_key"
        xqapi.api_auth_token = None
        xqapi.dashboard_auth_token = None
        # obj.loaddata()  # This will call your mock method
        return xqapi


@pytest.fixture
def mock_xq(mock_xqapi):
    # xq = XQ()
    # patch.object(xq, "__init__", None)
    # xq.api = mock_xqapi

    # return xq

    with mock.patch.object(XQ, "__init__", new=mock_init):
        xq = XQ()
        patch.object(xq, "__init__", None)
        xq.api = mock_xqapi

        return xq
