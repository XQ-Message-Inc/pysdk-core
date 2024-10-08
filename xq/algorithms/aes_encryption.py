from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Util import Counter
from xq.algorithms import Encryption
import os

class AESEncryption(Encryption):
    """AES implemented encryption algorithm"""

    def __init__(self, key: bytes, scheme: int = 1):
        """Initialize AESEncryption class with an encryption key"""
        
        Encryption.__init__(self, key)
        self.scheme = scheme
        
    def add_header_salt(self, header=None, salt_size=16, iv_size=12):
        """Generates a salt and IV, and adds them to the header"""

        salt = os.urandom(salt_size)
        iv = os.urandom(iv_size)
        salt_code = b'Salted__'

        if header is None:
            # Create a new header with salt_code, salt, and iv
            header = bytearray(8 + salt_size + iv_size)
            header[:8] = salt_code 
            header[8:8 + salt_size] = salt  
            header[8 + salt_size:] = iv 
        else:
            # Expand the existing header and append salt_code, salt, and iv
            expanded = bytearray(len(header) + 8 + salt_size + iv_size)
            expanded[:len(header)] = header 
            expanded[len(header):len(header) + 8] = salt_code 
            expanded[len(header) + 8:len(header) + 8 + salt_size] = salt  
            expanded[len(header) + 8 + salt_size:] = iv  
            header = expanded

        return {"header": header, "salt": salt, "iv": iv}
    
    def derive_key(self, salt: bytes, password: bytes = None, iterations: int = 1024, key_length: int = 32):
        """Derives a key using PBKDF2 with HMAC-SHA256."""
        key = PBKDF2(password, salt, dkLen=key_length, count=iterations, hmac_hash_module=SHA256)
        return key

    def encrypt(self, data: str, password: str=None, header=None):
        """Encrypts the provided data using AES-GCM"""
        if password is None:
            password = self.key
        
        if isinstance(password, str):
            password = password.encode()

        # Add salt and iv to the header
        if self.scheme == 2:
            context = self.add_header_salt(header, iv_size=16)
        else:
            context = self.add_header_salt(header)
        header = context['header']
        salt = context['salt']
        iv = context['iv']

        # Derive key using PBKDF2
        if self.scheme == 2:
            key = self.derive_key(salt, password, iterations=2048)
        else:
            key = self.derive_key(salt, password)

        if self.scheme == 2:
            counter_value = int.from_bytes(iv[:8], byteorder='big') << 64
            counter = Counter.new(128, initial_value=counter_value)
            cipher = AES.new(key, AES.MODE_CTR, counter=counter)
        else:
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        
        if isinstance(data, str):
            data = data.encode()
        
        combined = bytearray()

        if self.scheme == 2:
            ciphertext = cipher.encrypt(data)
            # Return the combined result: Header + Ciphertext
            combined.extend(header)
            combined.extend(ciphertext)
        else:
            ciphertext, tag = cipher.encrypt_and_digest(data)
            # Return the combined result: Header + Ciphertext + Tag
            combined.extend(header)      
            combined.extend(ciphertext)   
            combined.extend(tag)          

        return combined

    def decrypt(self, data: bytes, password: str = None, salt_size=16, iv_size=12):
        if password is None:
            password = self.key
        
        if isinstance(password, str):
            password = password.encode()
        
        if self.scheme == 2:
            iv_size = 16

        salted_marker = b'Salted__'
        start_pos = data.find(salted_marker)
        if start_pos == -1:
            raise ValueError("Invalid data format")
        
        salt_start = start_pos + len(salted_marker)
    
        salt = data[salt_start:salt_start + salt_size]

        iv_start = salt_start + salt_size
        iv = data[iv_start:iv_start + iv_size]

        ciphertext_start = iv_start + iv_size

        if self.scheme == 2:
            ciphertext = data[ciphertext_start:]
        else:
            ciphertext_end = -16
            ciphertext = data[ciphertext_start:ciphertext_end]
            tag = data[ciphertext_end:]

        # Derive the key using PBKDF2 and the extracted salt
        if self.scheme == 2:
            key = self.derive_key(salt, password, iterations=2048)
        else:   
            key = self.derive_key(salt , password)

        if self.scheme == 2:
            counter_value = int.from_bytes(iv[:8], byteorder='big') << 64
            counter = Counter.new(128, initial_value=counter_value)
            cipher = AES.new(key, AES.MODE_CTR, counter=counter)
            plaintext = cipher.decrypt(ciphertext)
        else:
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        return plaintext.decode("utf-8")
