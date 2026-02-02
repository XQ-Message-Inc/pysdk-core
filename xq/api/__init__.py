import requests

from xq.config import API_KEY, DASHBOARD_API_KEY, XQ_LOCATOR_KEY, API_BASE_URI
from xq.exceptions import SDKConfigurationException

class XQAPI:

    # import submodules as methods
    from xq.api.subscription import (
        validate_api_key,
        authorize_user,
        code_validate,
        exchange_key,
        exchange_for_subscription_token,
        create_packet,
        create_and_store_packet,
        create_and_store_packets,
        create_and_store_packets_batch,
        authorize_alias,
        authorize_device,
        authorize_device_cert
    )
    from xq.api.validation import (
        get_packet,
        get_packets,
        add_packet,
        revoke_packet,
        grant_users,
        revoke_users,
    )
    from xq.api.quantum import get_entropy
    from xq.api.manage import (
        dashboard_signup,
        dashboard_login,
        create_usergroup,
        get_usergroup,
        update_usergroup,
        delete_usergroup,
        add_contact,
        send_login_link,
        validate_access_token,
        login_verify,
        get_communication_by_locator_token,
        add_labels_to_locator_token,
        announce_device,
        exchange_for_dashboard_token,
        get_businesses,
        get_business_info,
        switch_business,
        generate_device_certificate
    )

    def __init__(
        self,
        api_key=API_KEY,
        dashboard_api_key=DASHBOARD_API_KEY,
        locator_key=XQ_LOCATOR_KEY,
        api_base_uri=API_BASE_URI,
    ):

        self.api_key = api_key
        self.dashboard_api_key = dashboard_api_key
        self.locator_key = locator_key
        self.api_base_uri = api_base_uri
        self.session = requests.Session()
        
        # Separate authorization tokens for each service
        self.api_auth_token = None
        self.dashboard_auth_token = None
        
        self.headers = {
            "authorization": "Bearer xyz123",
            "Content-Type": "application/json",
        }

        if not (self.api_key and self.dashboard_api_key):
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
        self._ensure_api_key_for_subdomain(subdomain)
        
        r = self.session.get(
            f"https://{subdomain}.{self.api_base_uri}{serviceEndpoint}",
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
        self._ensure_api_key_for_subdomain(subdomain)

        r = self.session.post(
            f"https://{subdomain}.{self.api_base_uri}{serviceEndpoint}",
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
        self._ensure_api_key_for_subdomain(subdomain)

        r = self.session.put(
            f"https://{subdomain}.{self.api_base_uri}{serviceEndpoint}",
            json=json,
            data=data,
            headers=self.headers,
        )

        try:
            res = r.json()
        except Exception as e:
            res = r.text

        return r.status_code, res

    def api_delete(self, serviceEndpoint, subdomain):
        """static method for interacting with XQ API DELETE endpoints

        :param serviceEndpoint: uri service extension to hit
        :type serviceEndpoint: string
        :param subdomain: subdomain of uri to use, api specific
        :type subdomain: string
        :return: status code, response
        :rtype: tuple(int, string)
        """
        self._ensure_api_key_for_subdomain(subdomain)

        r = self.session.delete(
            f"https://{subdomain}.{self.api_base_uri}{serviceEndpoint}",
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
        self._ensure_api_key_for_subdomain(subdomain)

        r = self.session.patch(
            f"https://{subdomain}.{self.api_base_uri}{serviceEndpoint}",
            data=data,
            json=json,
            headers=self.headers,
        )

        try:
            res = r.json()
        except Exception as e:
            res = r.text

        return r.status_code, res

    def set_api_auth_token(self, token: str):
        """Set the authorization token for the regular API service.
        
        :param token: Bearer token for API authorization
        :type token: string
        """
        self.api_auth_token = token
    
    def set_dashboard_auth_token(self, token: str):
        """Set the authorization token for the dashboard service.
        
        :param token: Bearer token for dashboard authorization
        :type token: string
        """
        self.dashboard_auth_token = token

    def _ensure_api_key_for_subdomain(self, subdomain: str):
        """Set the appropriate `api-key` and `authorization` headers depending on the subdomain.

        If the subdomain contains 'dashboard' use `DASHBOARD_API_KEY` and dashboard auth token,
        otherwise use the standard `self.api_key` and API auth token.
        """
        try:
            if subdomain and "dashboard" in subdomain:
                self.headers["api-key"] = DASHBOARD_API_KEY
                # Use dashboard auth token if available
                if self.dashboard_auth_token:
                    self.headers["authorization"] = f"Bearer {self.dashboard_auth_token}"
            else:
                self.headers["api-key"] = self.api_key
                # Use API auth token if available
                if self.api_auth_token:
                    self.headers["authorization"] = f"Bearer {self.api_auth_token}"
        except Exception:
            # fallback to existing api_key if something unexpected occurs
            self.headers["api-key"] = self.api_key
