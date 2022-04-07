from typing import TextIO, BinaryIO
from io import StringIO, BytesIO
from urllib.parse import quote_plus
import warnings

from xq.algorithms import Encryption
from xq.exceptions import SDKEncryptionException


class OTPEncryption(Encryption):
    def __init__(self, key: bytes):
        key_string = key if isinstance(key, str) else key.decode()
        self.expandedKey = self.expandKey(key_string, 2048).encode()
        Encryption.__init__(self, key)

        if self.expandedKey != self.originalKey:
            warnings.warn(
                "The provided key was expanded.  Make sure you save your reference of `Encryption.key`. i.e. `newKey = EncryptionObj.key`"
            )

    def xor_bytes(self, key: bytes, text: bytes):
        # replicated from jssdk-core

        # length = min(len(key), len(text))
        # return bytes([key[i] ^ text[i] for i in range(length)])

        return bytes([text[i] ^ key[i] for i in range(len(text))])

    def encrypt(self, msg):
        if isinstance(msg, str):
            # string support
            text = msg.encode()
        elif isinstance(msg, TextIO) or isinstance(msg, StringIO):
            # string file
            text = msg.getvalue().encode()
            print("file bytes:", text)
        elif isinstance(msg, BinaryIO) or isinstance(msg, BytesIO):
            # binary file
            text = msg.getvalue()
        else:
            raise SDKEncryptionException(f"Message type {type(msg)} is not supported!")

        return self.xor_bytes(self.expandedKey, text)

    def decrypt(self, text: bytes):
        return self.xor_bytes(self.expandedKey, text).decode()

    def encrypt_file(self, file: TextIO):
        pass

    def decrypt_file(self, file: TextIO):
        pass
