import requests
import os
import requests
import importlib

from xq.config import API_KEY, DASHBOARD_API_KEY, API_BASE_URI
from xq.exceptions import XQException, SDKConfigurationException


class XQAPI:

    # import submodules as methods
    from xq.api.subscription import (
        validate_api_key,
        authorize_user,
        code_validate,
        exchange_key,
        create_packet,
        store_packet,
    )
    from xq.api.validation import get_packet

    def __init__(
        self,
        api_key=API_KEY,
        dashboard_api_key=DASHBOARD_API_KEY,
        api_base_uri=API_BASE_URI,
    ):

        self.api_key = api_key
        self.dashboard_api_key = dashboard_api_key
        self.api_base_uri = api_base_uri
        self.headers = {
            "authorization": "Bearer xyz123",
            "Content-Type": "application/json",
        }

        if not (self.api_key and self.dashboard_api_key):
            raise SDKConfigurationException
        else:
            self.headers["api-key"] = self.api_key
            self.validate_api_key()

    # def __getattr__(self, attr):
    #     print(attr, 'not found')
    #     method_to_call = importlib.import_module(f'xq.api.{attr}')
    #     print('method_to_call', method_to_call)
    #     method_to_call(self)  # call submodule as method

    def api_get(self, serviceEndpoint, subdomain, params={}):
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
        r = requests.get(
            f"https://{subdomain}.{self.api_base_uri}{serviceEndpoint}",
            params=params,
            headers=self.headers,
        )

        try:
            res = r.json()
        except Exception as e:
            res = r.text

        return r.status_code, res

    def api_post(self, serviceEndpoint, subdomain, data={}):
        r = requests.post(
            f"https://{subdomain}.{self.api_base_uri}{serviceEndpoint}",
            json=data,
            headers=self.headers,
        )

        try:
            res = r.json()
        except Exception as e:
            res = r.text

        return r.status_code, res
