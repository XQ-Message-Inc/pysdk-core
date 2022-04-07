from typing import TextIO, BinaryIO
from io import StringIO, BytesIO
from urllib.parse import quote_plus
import warnings

from xq.algorithms import Encryption
from xq.exceptions import SDKEncryptionException


class OTPEncryption(Encryption):
    def __init__(self, key: bytes, max_encryption_chunk_size=2048):
        self.max_encryption_chunk_size = max_encryption_chunk_size
        key_string = key if isinstance(key, str) else key.decode()
        self.expandedKey = self.expandKey(
            key_string, self.max_encryption_chunk_size
        ).encode()

        Encryption.__init__(self, key)

        if self.expandedKey != self.originalKey:
            warnings.warn(
                "The provided key was expanded!  Make sure you save your reference of `Encryption.key`. i.e. `newKey = EncryptionObj.key`"
            )

    def xor_bytes(self, key: bytes, text: bytes):
        # replicated from jssdk-core
        print(len(key), len(text))

        return bytes([text[i] ^ key[i] for i in range(len(text))])

    def xor_chunker(self, text):
        b: bytes = b""
        for textChunk in [
            text[i : i + self.max_encryption_chunk_size]
            for i in range(0, len(text), self.max_encryption_chunk_size)
        ]:
            print("chunk len:", len(textChunk))
            print(type(textChunk))
            b = b + self.xor_bytes(self.expandedKey, textChunk)
        return b

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

        return self.xor_chunker(text)

    def decrypt(self, text: bytes):
        return self.xor_chunker(text).decode()

    def encrypt_file(self, file: TextIO):
        pass

    def decrypt_file(self, file: TextIO):
        pass
