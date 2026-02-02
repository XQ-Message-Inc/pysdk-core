import requests

from xq.config import API_KEY, XQ_LOCATOR_KEY, API_BASE_URI, XQ_URI_SCHEME
from xq.exceptions import SDKConfigurationException

class XQAPI:

    # import submodules as methods
    from xq.api.subscription import (
        validate_api_key,
        authorize_user,
        authorize_alias,
        code_validate,
        exchange_key,
        create_and_store_packet,
        create_and_store_packets,
        create_and_store_packets_batch,
        login_certificate
    )
    from xq.api.validation import (
        get_packet,
        get_packets,
        revoke_packet,
        grant_users,
        revoke_users,
    )
    from xq.api.quantum import get_entropy
    from xq.api.manage import (
        create_usergroup,
        get_usergroup,
        get_teams,
        create_team,
        switch,
        delete_team,
        update_usergroup,
        delete_usergroup,
        add_team_member,
        delete_team_member,
        send_login_link,
        login_alias,
        validate_access_token,
        login_verify,
        get_communication_by_locator_token,
        add_labels_to_locator_token,
        create_certificate,
        delete_certificate,
        get_teams,
        get_registered_teams
    )

    def __init__(
        self,
        api_key=API_KEY,
        locator_key=XQ_LOCATOR_KEY,
        api_base_uri=API_BASE_URI,
        api_scheme=XQ_URI_SCHEME,
    ):

        self.api_key = api_key
        self.locator_key = locator_key
        self.api_base_uri = api_base_uri
        self.api_scheme = api_scheme
        self.session = requests.Session()
        self.headers = {
            "Content-Type": "application/json",
        }

        if not (self.api_key):
            raise SDKConfigurationException
        else:
            self.headers["api-key"] = self.api_key
            self.validate_api_key()

    def api_get(self, serviceEndpoint, subdomain, params={}):
        """static method for interacting with the XQ API GET endpoints

        :param serviceEndpoint: uri service extension to hit
        :type serviceEndpoint: string
        :param subdomain: subdomain of uri to use, api specific
        :type subdomain: string
        :param params: optional parameters to pass, defaults to {}
        :type params: dict
        :param headers: optional headers to pass, defaults to {}
        :type headers: dict
        :return: requests obj
        :rtype: requests response
        """
        subdomainText = f"{subdomain}." if "/v2/" in self.api_base_uri else ""
        r = self.session.get(
            f"{self.api_scheme}://{subdomainText}{self.api_base_uri}{serviceEndpoint}",
            params=params,
            headers=self.headers,
        )

        try:
            res = r.json()
        except Exception as e:
            res = r.text

        return r.status_code, res

    def api_post(self, serviceEndpoint, subdomain, json=None, data=None):
        """static method for interacting with XQ API POST endpoints

        :param serviceEndpoint: uri service extension to hit
        :type serviceEndpoint: string
        :param subdomain: subdomain of uri to use, api specific
        :type subdomain: string
        :param json: optional parameters to pass, POSTS as json contenttype, defaults to None
        :type json: dict, optional
        :param data: optional parameters to pass, defaults to None
        :type data: dict, optional
        :return: status code, response
        :rtype: tuple(int, string)
        """
        subdomainText = f"{subdomain}." if "/v2/" in self.api_base_uri else ""
        r = self.session.post(
            f"{self.api_scheme}://{subdomainText}{self.api_base_uri}{serviceEndpoint}",
            json=json,
            data=data,
            headers=self.headers,
            timeout=30,
        )

        try:
            res = r.json()
        except Exception as e:
            res = r.text

        return r.status_code, res

    def api_put(self, serviceEndpoint, subdomain, json=None, data=None):
        """static method for interacting with XQ API PUT endpoints

        :param serviceEndpoint: uri service extension to hit
        :type serviceEndpoint: string
        :param subdomain: subdomain of uri to use, api specific
        :type subdomain: string
        :param json: optional parameters to pass, POSTS as json contenttype, defaults to None
        :type json: dict, optional
        :param data: optional parameters to pass, defaults to None
        :type data: dict, optional
        :return: status code, response
        :rtype: tuple(int, string)
        """

        subdomainText =  f"{subdomain}." if "/v2/" in self.api_base_uri else ""

        r = self.session.put(
            f"{self.api_scheme}://{subdomainText}{self.api_base_uri}{serviceEndpoint}",
            json=json,
            data=data,
            headers=self.headers,
        )

        try:
            res = r.json()
        except Exception as e:
            res = r.text

        return r.status_code, res

    def api_delete(self, serviceEndpoint, subdomain, json=None):
        """static method for interacting with XQ API DELETE endpoints

        :param serviceEndpoint: uri service extension to hit
        :type serviceEndpoint: string
        :param subdomain: subdomain of uri to use, api specific
        :type subdomain: string
        :return: status code, response
        :rtype: tuple(int, string)
        """
        subdomainText =  f"{subdomain}." if "/v2/" in self.api_base_uri else ""

        r = self.session.delete(
            f"{self.api_scheme}://{subdomainText}{self.api_base_uri}{serviceEndpoint}",
            json=json,
            headers=self.headers,
        )

        try:
            res = r.json()
        except Exception as e:
            res = r.text

        return r.status_code, res

    def api_patch(self, serviceEndpoint, subdomain, data=None, json=None):
        """static method for interacting with XQ API PATCH endpoints

        :param serviceEndpoint: uri service extension to hit
        :type serviceEndpoint: string
        :param subdomain: subdomain of uri to use, api specific
        :type subdomain: string
        :param data: optional parameters to pass, defaults to None
        :type data: dict, optional
        :param json: optional parameters to pass, POSTS as json contenttype, defaults to None
        :type json: dict, optional
        :return: status code, response
        :rtype: tuple(int, string)
        """

        subdomainText =  f"{subdomain}." if "/v2/" in self.api_base_uri else ""

        r = self.session.patch(
            f"{self.api_scheme}://{subdomainText}{self.api_base_uri}{serviceEndpoint}",
            data=data,
            json=json,
            headers=self.headers,
        )

        try:
            res = r.json()
        except Exception as e:
            res = r.text

        return r.status_code, res
