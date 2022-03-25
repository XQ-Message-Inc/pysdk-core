from xq.exceptions.xq import XQException
from ._version import get_versions
import os
import requests


from xq.config import API_KEY, DASHBOARD_API_KEY, API_BASE_URI, API_HEADERS
from xq.exceptions import SDKConfigurationException
from xq.algorithms import Algorithms

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

    def api_get(self, serviceEndpoint, params={}):
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
            f"{API_BASE_URI}{serviceEndpoint}", params=params, headers=API_HEADERS
        )

        try:
            res = r.json()
        except Exception as e:
            res = r.text

        return r.status_code, res

    def api_post(self, serviceEndpoint, data={}):
        r = requests.post(
            f"{API_BASE_URI}{serviceEndpoint}", json=data, headers=API_HEADERS
        )

        try:
            res = r.json()
        except Exception as e:
            res = r.text

        return r.status_code, res

    def validate_api_key(self):
        """static method for validating provided API keys

        :raises SDKConfigurationException: exception for invalid keys
        """
        status_code, res = self.api_get("apikey")

        if status_code == 200:
            return res
        if status_code == 401:
            raise SDKConfigurationException(message="The provided API Key is not valid")
        else:
            raise SDKConfigurationException(
                message=f"Failed to verify API key, error: {status_code} - {res}"
            )

    def authorize_user(
        self, user, firstName, lastName, newsletter=False, notifications=0
    ):
        payload = {
            "user": user,
            "firstName": firstName,
            "lastName": lastName,
            "newsletter": newsletter,
            "notifications": notifications,
        }

        status_code, auth_token = self.api_post("authorize", data=payload)

        # update auth header to use new bearer token
        # TODO: move to method
        API_HEADERS["authorization"] = f"Bearer {auth_token}"

        if status_code == 200:
            return auth_token
        else:
            return False

    def authorize_alias(self, alias):
        status_code, auth_token = self.api_post("authorizealias", data={"user": alias})

        print(status_code, auth_token)
        return auth_token

    def code_validate(self, pin):
        status_code, res = self.api_get("codevalidation", params={"pin": pin})

        print(status_code, res)

        if str(status_code).startswith("20"):
            return True
        else:
            raise XQException(message="The provided pin is incorrect")

    def create_packet(self, recipients, expires_hours=24, auth_token=None):

        payload = {
            "recipients": recipients,
            "expires": expires_hours,
            "key": auth_token,
        }
        status_code, res = self.api_post("packet", data=payload)

        print(status_code, res)

        if status_code == 200:
            return True
        else:
            raise XQException(message=f"Packet creation failed: {res}")

    def store_packet(self, encrypted_key_packet):
        status_code, res = self.api_post(data=encrypted_key_packet)

        print(status_code, res)

    def encrypt_message(
        self, text, algorithm=Algorithms, recipients=[], expires_hours=24
    ):

        # 1. create key packet

        # 2. store key packet

        # 2. encrypt text

        pass
