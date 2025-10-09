from fileinput import filename
import re
import random
import math
import struct
import warnings
from io import BytesIO
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
    
    def encryptFile(self, filename, data, token, password, scheme=1, *, out_file=None, chunk_size=1024*1024):
        """
        Encrypt a file payload with outer XQ header + inner body.
        - GCM (scheme==1): in-memory unless out_file handling upstream writes.
        - CTR (scheme==2): streams when out_file is provided.
        - OTP (scheme=='B'): now supported; can stream to out_file too.
        :param data: file-like or bytes/str
        """
        if isinstance(password, str):
            password = password.encode()

        # Encrypt filename
        enc_filename = b""
        if filename:
            fn_bytes = filename.encode('utf-8') if isinstance(filename, str) else filename
            if scheme == 'B':  
                enc_filename = self.encrypt(fn_bytes, password)
            else:              
                enc_filename = self.encrypt(fn_bytes, password, header=None)

        # Build outer file header
        outer_header = self.create_file_header(enc_filename, token, scheme=scheme)
        
        if scheme == 'B':
            return self.encrypt_file_streaming(
                data,
                password,
                header=outer_header,
                out_file=out_file,            
                chunk_size=chunk_size,
            )
    
        # GCM: in-memory; CTR: stream if out_file is provided
        if scheme == 2:  # CTR
            if out_file is not None:
                out_file.write(outer_header)
                self.scheme = 2
                self.encrypt(data, password, header=None, chunk_size=chunk_size, out_file=out_file)
                return None
            else:
                self.scheme = 2
                if hasattr(data, "read"):
                    data = data.read()
                body_bytes = self.encrypt(data, password, header=None, chunk_size=chunk_size)
                return outer_header + body_bytes
        else:
            self.scheme = 1
            if hasattr(data, "read"):
                data = data.read()
            body_bytes = self.encrypt(data, password, header=None)
    
        return outer_header + body_bytes
    
    def decryptFile(self, data, password: bytes | str | None = None, out_file=None, chunk_size: int = 1024 * 1024):
        if password is None:
            password = self.key
        if isinstance(password, str):
            password = password.encode()
        if isinstance(password, (bytes, bytearray)) and len(password) >= 2 and password[:1] == b'.':
            password = password[2:]

        token_size = 43

        def _read_exact(fh, n: int) -> bytes:
            b = fh.read(n)
            if len(b) != n:
                raise ValueError("Truncated header")
            return b

        if hasattr(data, "read"):
            try:
                data.seek(0)
            except Exception:
                pass
            v = struct.unpack('<I', _read_exact(data, 4))[0]
            version = v - token_size
            if version not in (0, 1):
                raise ValueError(f"Incompatible header version: {version}")
            _ = _read_exact(data, token_size)                   
            name_size = struct.unpack('<I', _read_exact(data, 4))[0]
            if name_size < 0 or name_size > 2000:
                raise ValueError("Invalid filename size")
            name_enc = _read_exact(data, name_size)
            scheme = _read_exact(data, 1)[0] if version > 0 else 1
            body_stream = data                                   
            body_bytes = None
        else:
            buf = data
            view = memoryview(buf)
            off = 0
            v = struct.unpack_from('<I', view, off)[0]
            version = v - token_size
            if version not in (0, 1):
                raise ValueError(f"Incompatible header version: {version}")
            off += 4 + token_size
            name_size = struct.unpack_from('<I', view, off)[0]
            off += 4
            if name_size < 0 or name_size > 2000:
                raise ValueError("Invalid filename size")
            name_enc = bytes(view[off:off+name_size])
            off += name_size
            scheme = view[off] if version > 0 else 1
            if version > 0:
                off += 1
            body_bytes = bytes(view[off:])                       
            body_stream = None

        # CTR streams; GCM in-memory
        if scheme == 2:
            self.scheme = 2
            if out_file is not None:
                if body_stream is not None:
                    self.decrypt(body_stream, password, chunk_size=chunk_size, out_file=out_file)
                else:
                    self.decrypt(BytesIO(body_bytes), password, chunk_size=chunk_size, out_file=out_file)
                return None
            if body_stream is not None:
                body_bytes = body_stream.read()
            pt = self.decrypt(body_bytes, password, chunk_size=chunk_size)
            return pt if isinstance(pt, (bytes, bytearray)) else pt.encode("utf-8")
        else:
            self.scheme = 1  # GCM
            if body_stream is not None:
                body_bytes = body_stream.read()
            pt = self.decrypt(body_bytes, password)
            return pt if isinstance(pt, (bytes, bytearray)) else pt.encode("utf-8")
    
    def create_file_header(self, filename, token, scheme=1, version=1):
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
            buffer[tail] = scheme if isinstance(scheme, int) else ord(scheme)
        else:
            raise IndexError(f"Tail index {tail} is out of range for buffer length {len(buffer)}")

        return buffer