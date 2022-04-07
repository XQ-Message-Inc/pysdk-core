from Crypto.Cipher import AES

from xq.algorithms import Encryption
from xq.exceptions import SDKEncryptionException


class AESEncryption(Encryption):
    """_summary_

    :param Encryption: Inherited Parent class
    :type Encryption: Encryption class
    """

    def __init__(self, key: bytes, nonce: bytes = None):
        """Initialize AESEncryption class with an encryption key and optional nonce, if decrypting

        :param key: encryption key
        :type key: bytes
        :param nonce: nonce from a previous encryption call, defaults to None
        :type nonce: bytes, optional
        """
        Encryption.__init__(self, key)
        self.nonce = nonce

    def encrypt(self, text: str):
        """encryption method for encrypting a text string

        :param text: input text to encrypt
        :type text: str
        :return: ciphertext, nonce, and tag from the cipher encryption
        :rtype: tuple(bytes)
        """
        cipher = AES.new(self.key, AES.MODE_EAX)
        self.nonce = cipher.nonce

        ciphertext, tag = cipher.encrypt_and_digest(text.encode("utf8"))

        return ciphertext, self.nonce, tag

    def decrypt(self, ciphertext: bytes, verificationTag: bytes = None):
        """decryption method for decrypting a text string

        :param ciphertext: the encrypted text, in bytes
        :type ciphertext: bytes
        :param verificationTag: verification tag created by encrypt, defaults to None
        :type verificationTag: bytes, optional
        :raises SDKEncryptionException: SDK decryption error
        :return: decrypted string
        :rtype: str
        """
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
