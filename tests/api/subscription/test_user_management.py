import pytest
from unittest.mock import MagicMock

from xq.api.subscription.user_management import *


def test_authorize_user_200(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(200, "mock server success"))
    assert authorize_user(mock_xqapi, "mockusername", "Mock", "Mocker")


def test_authorize_user_error(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(500, "mock server error"))
    assert authorize_user(mock_xqapi, "mockusername", "Mock", "Mocker") is False


def test_authorize_alias_200(mock_xqapi):
    mock_xqapi.api_post = MagicMock(return_value=(200, "mock server error"))
    assert authorize_alias(mock_xqapi, "mockalias")


def test_authorize_alias_error(mock_xqapi):
    pass  # TODO: build authorizealias
