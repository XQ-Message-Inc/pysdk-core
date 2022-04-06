from unittest import mock
import pytest
from unittest.mock import patch, MagicMock


@pytest.fixture
def mock_xqapi():

    with mock.patch("xq.XQAPI") as mock_api:
        mock_api.validate_api_key = MagicMock(
            return_value=True
        )  # override checking for valid provided keys
        xqapi = mock_api()  # create mocked instance

        xqapi.api_key = "mockapikey"  # set fake api key
        xqapi.dashboard_api_key = "mockdashboardkey"  # set fake dashboard key

        yield xqapi