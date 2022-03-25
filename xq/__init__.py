from ._version import get_versions
import os
from dotenv import load_dotenv


from xq.exceptions import SDKConfigurationException

__version__ = get_versions()["version"]
del get_versions


class XQ:
    def __init__(self, api_key=None, dashboard_api_key=None):
        """initializes the XQ SDK with API keys, in priority order:
            1. params
            2. ENV
            3. .env file

        :param api_key: _description_, defaults to None
        :type api_key: _type_, optional
        :param dashboard_api_key: _description_, defaults to None
        :type dashboard_api_key: _type_, optional
        """
        load_dotenv()
        self.api_key = api_key if api_key else os.environ.get("XQ_API_KEY", None)
        self.dashboard_api_key = (
            dashboard_api_key
            if dashboard_api_key
            else os.environ.get("XQ_DASHBOARD_API_KEY", None)
        )

        if not (self.api_key and self.dashboard_api_key):
            raise SDKConfigurationException
