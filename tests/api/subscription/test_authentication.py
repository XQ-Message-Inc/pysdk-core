from unittest import mock
import pytest
from unittest.mock import patch, MagicMock

from xq.api.subscription.authentication import *
from xq.api import XQAPI


@pytest.fixture
def validate_api_400():
    return (401, "{'status': 'Failed to locate API key'}")


@pytest.fixture
def validate_api_200():
    return (
        200,
        '{"scopes":["authorize","combine","exchange","packet","edit:settings","read:settings","read:subscriber","edit:subscriber","read:image","key","read:apikey","revoke","devapp","settings","delegate","subscriber"],"status":"OK"}',
    )


@patch.object(XQAPI, "api_get")
def test_validate_api_key_200(mock_api_call, validate_api_200):
    mock_api_call.return_value = validate_api_200
    assert validate_api_key(XQAPI())


@patch.object(XQAPI, "api_get")
def test_validate_api_key_400(mock_api_call, validate_api_400):
    mock_api_call.return_value = validate_api_400
    with pytest.raises(SDKConfigurationException):
        validate_api_key(XQAPI())


@patch.object(XQAPI, "api_get")
def test_validate_api_key_other(mock_api_call):
    mock_api_call.return_value = 500, "general server error"
    with pytest.raises(SDKConfigurationException):
        validate_api_key(XQAPI())


def test_code_validate_200(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(200, "never going to happen"))
    assert code_validate(mock_xqapi, 123456)


def test_code_validate_204(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(204, None))
    assert code_validate(mock_xqapi, 123456)


def test_code_validate_failure(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        code_validate(mock_xqapi, 123456)


def test_exchange_key(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(200, "{'contents': 'mock contents'}"))
    assert exchange_key(mock_xqapi)


def test_exchange_key_failure(mock_xqapi):
    mock_xqapi.api_get = MagicMock(return_value=(500, "mock server error"))
    with pytest.raises(XQException):
        exchange_key(mock_xqapi)
