from Crypto.Cipher import AES

from xq.algorithms import Encryption


class AESEncryption(Encryption):
    def __init__(self, text, key):
        Encryption.__init__(text, key)
        self.cipher = AES.new(self.key, AES.MODE_EAX)
        self.nonce = self.cipher.nonce

    def encrypt(self):
        print(self.text, self.key)

        ciphertext, tag = self.cipher.encrypt_and_digest(self.text)

        return ciphertext, tag

    def decrypt(self, ciphertext, tag):
        plaintext = self.cipher.decrypt(ciphertext)

        try:
            self.cipher.verify(tag)
            print("The message is authentic:", plaintext)
        except ValueError:
            print("Key incorrect or message corrupted")
