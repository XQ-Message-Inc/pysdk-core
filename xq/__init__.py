import typing
import io
import os
import base64
import struct
from typing import List
from ._version import get_versions
from xq.config import API_KEY, DASHBOARD_API_KEY, XQ_LOCATOR_KEY
from xq.algorithms import OTPEncryption, Encryption, Algorithms
from xq.exceptions import XQException
from xq.api import XQAPI  # import all api endpoint integrations
from typing import Dict
from io import BufferedReader


try:
    from xq.algorithms.xor import expand_key_python
except ImportError:
    expand_key_python = None

__version__ = get_versions()["version"]
del get_versions

class XQ:
    def __init__(self, api_key=API_KEY, dashboard_api_key=DASHBOARD_API_KEY, locator_key=XQ_LOCATOR_KEY):
        """initializes the XQ SDK with API keys, in priority order:
            1. params
            2. ENV
            3. .env file

        :param api_key: _description_, defaults to ENV value
        :type api_key: _type_, optional
        :param dashboard_api_key: _description_, defaults to ENV value
        :type dashboard_api_key: _type_, optional
        :param locator_key: _description_, defaults to ENV value
        :type locator_key: _type_, optional
        """
        self.api = XQAPI(api_key, dashboard_api_key, locator_key)  # bind api functions as methods

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
    
    def expand_key(self, data: bytes, key: bytes) -> bytes:
        """expand a key to the size of the text to be encrypted
        
        :param data: data you are going to encrypt
        :type data: bytes
        :param key: encryption key you were going to utilize to encrypt the data
        :type key: bytes, defaults to None
        :return: expanded key to utilize for encryption
        :rtype: bytes
        """
        if isinstance(key, str):
            key = key.encode()
        
        if isinstance(data, str):
            data = data.encode()

        if len(key) >= len(data):
            return key
        
        if expand_key_python is not None:
            return expand_key_python(data, key)
        else:
            return key

    def encrypt_message(self, text: str, key: bytes, algorithm: Algorithms = "OTP", recipients: List[str] = None):
        """encrypt a string

        :param text: string to encrypt
        :type text: str
        :param key: encryption key to use to encrypted text
        :type key: bytes, defaults to None
        :param algorithm: the encryption algorithm to use
        :type algorithm: Algorithms, defaults to OTP
        :return: ciphertext
        :rtype: bytes
        """
        encryptionAlgorithm = Algorithms[algorithm](key)

        if isinstance(key, str):
            key = key.encode()

        return encryptionAlgorithm.encrypt(text)

    def decrypt_message(
        self,
        encryptedText: bytes,
        key: bytes,
        algorithm: Algorithms = "OTP"
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
        if isinstance(key, str):
            key = key.encode()
        
        encryptionAlgorithm = Algorithms[algorithm](key)
        plaintext = encryptionAlgorithm.decrypt(encryptedText)
        return plaintext

    def encrypt_file(
        self, fileObj: typing.TextIO, key: bytes, algorithm: Algorithms = "OTP", recipients: List[str] = None, expires_hours: int = 24
    ) -> bytearray:
        """encrypt the contents of a given file object

        :param fileObj: FileLike object to encrypt
        :type fileObj: typing.TextIO
        :param key: encryption key to use, NOTE: may be expanded
        :type key: bytes
        :return: encrypted text, encryption key
        :rtype: tuple
        """
        
        if isinstance(key, str):
            key = key.encode()

        if isinstance(fileObj, str):
            fileObj = open(fileObj, "rb").read()

        if algorithm == "OTP":
            locator_token = self.api.create_and_store_packet(recipients=recipients, key=((b".B") + key), type="file", subject=os.path.basename(fileObj.name), expires_hours=expires_hours)
            encryptionAlgorithm = Algorithms[algorithm](key)
            ciphertext = encryptionAlgorithm.encryptFile(os.path.basename(fileObj.name), fileObj, locator_token, key)
            return ciphertext
        else:
            locator_token = self.api.create_and_store_packet(recipients=recipients, key=((b".2" if algorithm == "CTR" else b".1") + key), type="file", subject=os.path.basename(fileObj.name),  expires_hours=expires_hours)
            encryptionAlgorithm = Algorithms[algorithm](key, scheme=2 if algorithm == "CTR" else 1)
            ciphertext = encryptionAlgorithm.encryptFile(os.path.basename(fileObj.name), fileObj, locator_token, key)
            return ciphertext

    def decrypt_file(
        self,
        encryptedText: bytes | BufferedReader,
        key: bytes = None,
        algorithm: Algorithms = "OTP"
    ) -> io.StringIO:
        """decrypt a given bytes string back into a FileLike object

        :param encryptedText: encrypted file contents
        :type encryptedText: bytes
        :param key: encryption key
        :type key: bytes
        :return: FileLike StringIO handle
        :rtype: StringIO
        """
        if key is None:
            locator, name_encrypted, content_encrypted = self.parse_file_for_decrypt(encryptedText)
            key = self.api.get_packet(locator)
            encryptedText = content_encrypted

        if algorithm == "OTP":
            encryptionAlgorithm = Algorithms[algorithm](key)
            plaintext = encryptionAlgorithm.decryptFile(encryptedText)
            fh = plaintext
        else:
            encryptionAlgorithm = Algorithms[algorithm](key, scheme=2 if algorithm == "CTR" else 1)
            plaintext = encryptionAlgorithm.decryptFile(encryptedText)
            fh = plaintext

        return fh
    
    def parse_file_for_decrypt(self, input_data) -> Dict[str, bytes]:
        # Check if the input is a file (BufferedReader) or bytes
        if hasattr(input_data, 'read'):
            file_data_bytes = input_data.read()
        elif isinstance(input_data, bytes):
            file_data_bytes = input_data
        else:
            raise TypeError("Input must be a file-like object or bytes")

        # Fetch the length of the token (locatorSize)
        start = 0
        end = 4
        locator_size = struct.unpack('<I', file_data_bytes[start:end])[0]
        
        # Validate the locatorSize
        if locator_size > 256:
            raise ValueError("Unable to parse file, check that the file is valid and not damaged")
        
        # Fetch the locator string based on locatorSize
        start = end
        end = start + locator_size - 1
        locator = file_data_bytes[start:end].decode('utf-8')

        # Fetch the fileNameSize
        start = end
        end = start + 4
        file_name_size = struct.unpack('<I', file_data_bytes[start:end])[0]
        
        # Validate the fileNameSize
        if file_name_size < 2 or file_name_size > 2000:
            raise ValueError("Unable to parse file, check that the file is valid and not damaged")
        
        # Fetch the nameEncrypted (based on fileNameSize)
        start = end
        end = start + file_name_size - 1
        name_encrypted = file_data_bytes[start:end]

        content_encrypted = file_data_bytes

        return locator, name_encrypted, content_encrypted
