from typing import TextIO
from urllib.parse import quote_plus

from xq.algorithms import Encryption
from xq.exceptions import SDKEncryptionException


class OTPEncryption(Encryption):
    def __init__(self, key: bytes):
        Encryption.__init__(self, key)

    def xor_bytes(self, key: bytes, text: bytes):
        length = min(len(key), len(text))
        return bytes([key[i] ^ text[i] for i in range(length)])

    def encrypt(self, text: bytes):
        if isinstance(text, str):
            text = text.encode()

        return self.xor_bytes(self.key, text)

    def decrypt(self, text: bytes):
        return self.xor_bytes(self.key, text).decode()

    def encrypt_file(self, file: TextIO):
        pass

    def decrypt_file(self, file: TextIO):
        pass
