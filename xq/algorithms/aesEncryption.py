from Crypto.Cipher import AES

from xq.algorithms import Encryption
from xq.exceptions import SDKEncryptionException


class AESEncryption(Encryption):
    def __init__(self, key):
        Encryption.__init__(self, key)
        self.cipher = AES.new(self.key, AES.MODE_EAX)
        self.nonce = self.cipher.nonce

    def encrypt(self, text):
        print(text, self.key)

        ciphertext, tag = self.cipher.encrypt_and_digest(text.encode("utf8"))

        return ciphertext, tag

    def decrypt(self, ciphertext: bytes, verificationTag=None):
        plaintext = self.cipher.decrypt(ciphertext)

        if verificationTag:
            try:
                self.cipher.verify(verificationTag)
                print("The message is authentic:", plaintext)
            except ValueError:
                raise SDKEncryptionException(
                    "Provided key is incorrect or message is corrupted"
                )

        return plaintext
