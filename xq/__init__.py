from ._version import get_versions
import os
import requests

from xq.config import API_KEY, DASHBOARD_API_KEY, API_BASE_URI, API_HEADERS
from xq.exceptions import SDKConfigurationException

__version__ = get_versions()["version"]
del get_versions


class XQ:
    def __init__(self, api_key=API_KEY, dashboard_api_key=DASHBOARD_API_KEY):
        """initializes the XQ SDK with API keys, in priority order:
            1. params
            2. ENV
            3. .env file

        :param api_key: _description_, defaults to ENV value
        :type api_key: _type_, optional
        :param dashboard_api_key: _description_, defaults to ENV value
        :type dashboard_api_key: _type_, optional
        """
        self.api_key = api_key
        self.dashboard_api_key = dashboard_api_key

        if not (self.api_key and self.dashboard_api_key):
            raise SDKConfigurationException
        else:
            API_HEADERS["api-key"] = self.api_key
            self.validate_api_key()

    def api_call(self, serviceEndpoint, params={}):
        """static method for interacting with the XQ API

        :param serviceEndpoint: uri service extension to hit
        :type serviceEndpoint: string
        :param params: optional parameters to pass, defaults to {}
        :type params: dict
        :param headers: optional headers to pass, defaults to {}
        :type headers: dict
        :return: requests obj
        :rtype: requests response
        """
        API_HEADERS
        r = requests.get(
            f"{API_BASE_URI}{serviceEndpoint}", params=params, headers=API_HEADERS
        )

        return r.status_code, r.json()

    def validate_api_key(self):
        """static method for validating provided API keys

        :raises SDKConfigurationException: exception for invalid keys
        """
        status_code, res = self.api_call("apikey")

        if status_code == 200:
            return res
        if status_code == 401:
            raise SDKConfigurationException(message="The provided API Key is not valid")
        else:
            raise SDKConfigurationException(
                message=f"Failed to verify API key, error: {status_code} - {res}"
            )
