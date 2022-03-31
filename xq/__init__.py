from ._version import get_versions

from xq.config import API_KEY, DASHBOARD_API_KEY
from xq.exceptions import SDKConfigurationException, SDKEncryptionException
from xq.algorithms import Algorithms
from xq.api import XQAPI  # import all api endpoint integrations

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
        self.api = XQAPI(api_key, dashboard_api_key)  # bind api functions as methods

    def encrypt_message(
        self, text, key: bytes, algorithm: Algorithms, recipients=[], expires_hours=24
    ):
        encryptionAlgorithm = Algorithms[algorithm](key)
        print("encrypting:", text, "using:", encryptionAlgorithm)
        ciphertext, tag = encryptionAlgorithm.encrypt(text)
        print("-- encrypted text --")
        print(ciphertext, tag)
        return ciphertext, tag

    def decrypt_message(self, encryptedText: bytes, key, algorithm: Algorithms):
        encryptionAlgorithm = Algorithms[algorithm](key)
        print("using", encryptionAlgorithm)
        plaintext = encryptionAlgorithm.decrypt(encryptedText)
        return plaintext
