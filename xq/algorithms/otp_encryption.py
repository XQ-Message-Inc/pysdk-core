import warnings
from typing import TextIO, BinaryIO
from io import StringIO, BytesIO, TextIOWrapper, BufferedReader
from pathlib import PosixPath
from xq.algorithms import Encryption

try:
    from xq.algorithms.xor import xor_simd_neon_python
except ImportError:
    xor_simd_neon_python = None

class OTPEncryption(Encryption):
    """OTP implimented encryption algorithm

    :param Encryption: Inherited Parent class
    :type Encryption: Encryption class
    """

    def __init__(self, key: bytes, max_encryption_chunk_size=2048):
        """Initialize OTPEncryption class with an encryption key

        :param key: encryption key
        :type key: bytes
        :param max_encryption_chunk_size: the maximum byte chunk for encryption, defaults to 2048
        :type max_encryption_chunk_size: int, optional
        """
        self.max_encryption_chunk_size = max_encryption_chunk_size
        Encryption.__init__(self, key)

    def encrypt(self, msg: bytes):
        """encryption method for encrypting a bytes-string or bytes-file

        :param msg: message to encrypt
        :type msg: bytes OR FileLike
        :raises SDKEncryptionException: unsupported message type
        :return: encrypted message
        :rtype: bytes
        """

        if isinstance(msg, str):
            # string support
            warnings.warn(
                "A string was submitted for encryption, the decrypted result will be UTF-8 bytes!"
            )
            text = msg.encode()
        elif isinstance(msg, TextIO) or isinstance(msg, StringIO):
            # string file
            warnings.warn(
                "A string file was submitted for encryption, the decrypted result will be UTF-8 bytes!"
            )
            text = msg.getvalue().encode()
        elif isinstance(msg, BinaryIO) or isinstance(msg, BytesIO):
            # binary file
            text = msg.getvalue()
        elif isinstance(msg, PosixPath):
            # unix file
            text = msg.open("rb").read()
        elif isinstance(msg, TextIOWrapper):
            # text io
            warnings.warn(
                "A TextIO file was submitted for encryption, the decrypted result will be UTF-8 bytes!"
            )
            text = msg.read().encode()
        elif isinstance(msg, bytes):
            text = msg
        elif isinstance(msg, BufferedReader):
            # bytes file handle
            text = msg.read()
        else:
            # raise SDKEncryptionException(f"Message type {type(msg)} is not supported!")
            warnings.warn(
                f"Message type {type(msg)} is not officially supported, but trying anyway"
            )
            text = msg
        if xor_simd_neon_python is not None:
            # if len(text) > len(self.key):
            #     warnings.warn(
            #         f"Message length ({len(text)}) exceeds key length ({len(self.key)}). For enhanced security, consider expanding the key using the `expand_key` function."
            #     )
            return xor_simd_neon_python(text, self.key)
        else:
            return

    def decrypt(self, text: bytes) -> bytes:
        """decryption method for decrypting a string or file

        :param text: text to decrypt
        :type text: bytes
        :return: decrypted text
        :rtype: bytes
        """

        if xor_simd_neon_python is not None: 
            return xor_simd_neon_python(text, self.key)
        else:
            return
