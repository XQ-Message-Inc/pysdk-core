import re
import random
import math
import struct
import warnings
class Encryption:
    """parent class for all encryption algorithms"""

    def __init__(self, key: str):
        """initialize shared algorithm functionality

        :param key: encryption key
        :type key: bytes
        """
        self.originalKey = key.encode() if isinstance(key, str) else key

    @property
    def key(self):
        """method property that returns the correct key value used for encryption

        :return: key used for encryption
        :rtype: bytes
        """
        return self.originalKey

    def shuffle(self, string: str = None):
        """psudo-randomize a provided string
        * replicated from jssdk-core

        :param string: provided string to randomize
        :type string: str
        :return: randomized string
        :rtype: str
        """
        string = string if string else self.key
        string_list = list(string)
        for i in range(len(string_list) - 1, -1, -1):
            j = math.floor(random.uniform(0, 1) * (i + 1))
            tmp = string_list[i]
            string_list[i] = string_list[j]
            string_list[j] = tmp

        try:
            # try string of bytes
            bytes_string = bytes(string_list).decode()
            assert len(bytes_string) == len(
                string
            ), "unexpected shuffle! new length does not match original"

            return bytes_string
        except:
            # just a regular string
            return "".join(string_list)
    
    def encryptFile(self, filename, data, token, password):
        if filename:
                filename = filename.encode('utf-8')
            
        if filename:
            try:
                filename = self.encrypt(filename, password)
            except Exception as err:
                return None
            
        header = self.create_file_header(filename, token)

        data = data.read()
        encrypted = self.encrypt(data, password)

        return header + encrypted 
    
    def decryptFile(self, data: bytes, password: str = None):
        if password is None:
            password = self.key
        
        if isinstance(password, str):
            password = password.encode()
        
        if password[0] == ord('.'):
            password = password[2:]

        header = self.get_file_header(data, 1)
        buf = data[header["length"]:]

        # Originally the filename was encrypted to be obfuscated, but that is no longer the case as per client requests.
        decrypted_filename = self.decrypt(header["filename"], password)

        decrypted_data = self.decrypt(buf, password)
        
        if isinstance(decrypted_data, str):
            return decrypted_data.encode("utf-8")
        else:
            return decrypted_data
    
    def create_file_header(self, filename, token, version=1):
        token_size = 43
        token_bytes = token.encode('utf-8') 

        if isinstance(filename, str):
            name_bytes = filename.encode('utf-8') 
        else:
            name_bytes = filename

        name_size = len(name_bytes)
        tail = 0

        buffer = bytearray(4 + token_size + 4 + name_size + 1)

        struct.pack_into('I', buffer, tail, token_size + version)
        tail += 4

        buffer[tail:tail + token_size] = token_bytes
        tail += token_size

        struct.pack_into('I', buffer, tail, name_size)
        tail += 4

        if name_size > 0:
            buffer[tail:tail + name_size] = name_bytes
        tail += name_size

        if tail < len(buffer):
            buffer[tail] = 1
        else:
            raise IndexError(f"Tail index {tail} is out of range for buffer length {len(buffer)}")

        return buffer

    def get_file_header(self, data, version, token_size=43):
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("Expected data to be bytes or bytearray.")
        view = bytearray(data)

        tail = 0
        result = {"version": version, "length": 0}

        # Read the version (extract first 4 bytes and unpack as Uint32)
        v = struct.unpack('I', view[tail:tail + 4])[0] 
        result["version"] = v - token_size
        
        if result["version"] != version and v != token_size:
            warnings.warn(f'Cannot decrypt due to incompatible version: {result["version"]}')
            return result 

        tail += 4
        
        result["token"] = view[tail:tail + token_size].decode('utf-8')
        tail += token_size

        name_size = struct.unpack('I', view[tail:tail + 4])[0]
        tail += 4

        if name_size > 0:
            result["filename"] = view[tail:tail + name_size]
            tail += name_size
        else:
            result["filename"] = ""

        if result["version"] > 0:
            # Skip over the scheme (for compatibility)
            tail += 1

        result["length"] = tail
        return result
