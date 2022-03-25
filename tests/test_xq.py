import pytest
from unittest.mock import patch

from xq import *
from xq.exceptions import SDKConfigurationException
from xq import config


@pytest.fixture
def key_verify_failure():
    return (401, "{'status': 'Failed to locate API key'}")


@pytest.fixture
def key_verify_success():
    return (
        200,
        "{'scopes': ['authorize', 'combine', 'exchange', 'packet', 'edit:settings', 'read:settings', 'read:subscriber', 'edit:subscriber', 'read:image', 'key', 'read:apikey', 'revoke', 'devapp', 'settings', 'delegate', 'subscriber'], 'status': 'OK'}",
    )


@patch.object(XQ, "api_get")
def test_xq_environ(mock_api_call, key_verify_success):
    mock_api_call.return_value = key_verify_success
    os.environ["XQ_API_KEY"] = "mockapikey"
    os.environ["XQ_DASHBOARD_API_KEY"] = "mockdashboardkey"
    assert XQ(api_key="mockapikey", dashboard_api_key="mockdashboardkey")


@patch.object(XQ, "api_get")
def test_xq_input(mock_api_call, key_verify_success):
    mock_api_call.return_value = key_verify_success
    assert XQ(api_key="mockapikey", dashboard_api_key="mockdashboardkey")


@patch.object(XQ, "api_get")
def test_valid_api_key(mock_api_call, key_verify_success):
    mock_api_call.return_value = key_verify_success
    XQ(api_key="mockapikey", dashboard_api_key="mockdashboardkey")


@patch.object(XQ, "api_get")
def test_invalid_api_key(mock_api_call, key_verify_failure):
    mock_api_call.return_value = key_verify_failure
    with pytest.raises(SDKConfigurationException):
        XQ(api_key="mockapikey", dashboard_api_key="mockdashboardkey")
