import typing
import io

from ._version import get_versions
from xq.config import API_KEY, DASHBOARD_API_KEY
from xq.exceptions import SDKConfigurationException, SDKEncryptionException
from xq.algorithms import OTPEncryption, Encryption, Algorithms
from xq.exceptions import XQException
from xq.api import XQAPI  # import all api endpoint integrations
import base64

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

    def generate_key_from_entropy(self):
        """helper method for automatically requesting entropy and shuffling key

        :return: generated encryption key from entropy
        :rtype: bytes
        """

        # get XQ entropy
        entropy = self.api.get_entropy(entropy_bits=128)

        # decode base64 to string
        decodedEntropyBytes = base64.b64decode(entropy)

        # shuffle key
        enc = Encryption(decodedEntropyBytes.decode())
        generatedKey = enc.shuffle().encode()

        # ensure shuffeled key did add or loss information
        assert len(decodedEntropyBytes) == len(generatedKey)

        return generatedKey

    def encrypt_message(self, text: str, key: bytes, algorithm: Algorithms = "AES"):
        """encrypt a string

        :param text: string to encrypt
        :type text: str
        :param key: encryption key to use to encrypted text
        :type key: bytes, defaults to None
        :param algorithm: the encryption algorithm to use
        :type algorithm: Algorithms, defaults to AES
        :return: ciphertext, nonce, tag from encryption
        :rtype: tuple(bytes)
        """
        if isinstance(key, str):
            key = key.encode()

        encryptionAlgorithm = Algorithms[algorithm](key)
        ciphertext, nonce, tag = encryptionAlgorithm.encrypt(text)

        return ciphertext, nonce, tag

    def decrypt_message(
        self,
        encryptedText: bytes,
        key: bytes,
        algorithm: Algorithms = "AES",
        nonce: bytearray = None,
    ):
        """decrypt a previoulsy encrypted string

        :param encryptedText: encrypted text to decrypt
        :type encryptedText: bytes
        :param key: encryption key used to encrypt/decrypt
        :type key: bytes
        :param algorithm: algorithm used to encrypt/decrypt
        :type algorithm: Algorithms
        :param nonce: nonce provided from original encryption
        :type nonce: bytearray
        :return: decrypted text
        :rtype: str
        """
        if algorithm != "OTP" and not nonce:
            raise XQException("`nonce` is required for {algorithm} encryption")

        if isinstance(key, str):
            key = key.encode()

        encryptionAlgorithm = Algorithms[algorithm](key, nonce=nonce)
        plaintext = encryptionAlgorithm.decrypt(encryptedText)

        return plaintext

    def encrypt_file(self, fileObj: typing.TextIO, key: bytes) -> bytearray:
        """encrypt the contents of a given file object

        :param fileObj: FileLike object to encrypt
        :type fileObj: typing.TextIO
        :param key: encryption key to use, NOTE: may be expanded
        :type key: bytes
        :return: encrypted text, encryption key
        :rtype: tuple
        """
        if isinstance(fileObj, str):
            fileObj = open(fileObj, "r")

        otp = OTPEncryption(key)
        ciphertext = otp.encrypt(fileObj)

        return ciphertext, otp.key

    def decrypt_file(self, encryptedText: bytes, key: bytes) -> io.StringIO:
        """decrypt a given bytes string back into a FileLike object

        :param encryptedText: encrypted file contents
        :type encryptedText: bytes
        :param key: encryption key
        :type key: bytes
        :return: FileLike StringIO handle
        :rtype: StringIO
        """
        otp = OTPEncryption(key)
        plaintext = otp.decrypt(encryptedText)
        fh = io.StringIO(plaintext)

        return fh

    def magic_encrypt(self, thing_to_encrypt: any, recipients):
        #   1. generate key
        KEY = self.generate_key_from_entropy()
        encrypted_key_packet = self.api.create_packet(recipients=recipients, key=KEY)

        #   2. store key packet
        locator_token = self.api.add_packet(encrypted_key_packet)

        #   3. encrypt
        if isinstance(thing_to_encrypt, str):
            return locator_token, self.encrypt_message(
                thing_to_encrypt,
                key=KEY,
                algorithm="AES",
                recipients=recipients,
            )
        else:
            return locator_token, self.encrypt_file(thing_to_encrypt, key=KEY)

        # get key packet by lookup
        retrieved_key_packet = xq.api.get_packet(locator_token)

        #   4. save key in xq

        #   4. return locator token for key and encrypted message/file content
        pass

    def magic_decrypt(magic_bundle):

        if len(magic_bundle) == 4:
            # AES bundle - locator_token, encrypted_message, nonce, tag
            locator_token, encrypted_message, nonce, tag = magic_bundle

        else:
            # OTP bundle - locator_token, encryptedText, expanded_key
            locator_token, encryptedText, expanded_key = magic_bundle
