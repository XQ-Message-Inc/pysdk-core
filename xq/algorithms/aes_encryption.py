from Crypto.Cipher import AES

from xq.algorithms import Encryption
from xq.exceptions import SDKEncryptionException


class AESEncryption(Encryption):
    def __init__(self, key, nonce=None):
        Encryption.__init__(self, key)
        self.nonce = nonce

    def encrypt(self, text):
        cipher = AES.new(self.key, AES.MODE_EAX)
        self.nonce = cipher.nonce

        ciphertext, tag = cipher.encrypt_and_digest(text.encode("utf8"))

        return ciphertext, self.nonce, tag

    def decrypt(self, ciphertext: bytes, verificationTag=None):
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=self.nonce)
        plaintext = cipher.decrypt(ciphertext)

        if verificationTag:
            try:
                cipher.verify(verificationTag)
                print("The message is authentic:", plaintext)
            except ValueError:
                raise SDKEncryptionException(
                    "Provided key is incorrect or message is corrupted"
                )

        return plaintext.decode("utf8")
