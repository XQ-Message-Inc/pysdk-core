import os
import base64
import struct
from typing import List, BinaryIO, Union
from ._version import get_versions
from xq.config import API_KEY, DASHBOARD_API_KEY, XQ_LOCATOR_KEY
from xq.algorithms import Encryption, Algorithms
from xq.exceptions import XQException
from xq.api import XQAPI  

try:
    from xq.algorithms.xor import expand_key_python
except ImportError:
    expand_key_python = None

__version__ = get_versions()["version"]
del get_versions

class XQ:
    def __init__(self, api_key=API_KEY, dashboard_api_key=DASHBOARD_API_KEY, locator_key=XQ_LOCATOR_KEY):
        """initializes the XQ SDK with API keys, in priority order:
            1. params
            2. ENV
            3. .env file

        :param api_key: _description_, defaults to ENV value
        :type api_key: _type_, optional
        :param dashboard_api_key: _description_, defaults to ENV value
        :type dashboard_api_key: _type_, optional
        :param locator_key: _description_, defaults to ENV value
        :type locator_key: _type_, optional
        """
        self.api = XQAPI(api_key, dashboard_api_key, locator_key)  # bind api functions as methods

    def generate_key_from_entropy(self):
        """helper method for automatically requesting entropy and shuffling key

        :return: generated encryption key from entropy
        :rtype: bytes
        """

        # get XQ entropy
        entropy = self.api.get_entropy(entropy_bits=128)

        # decode base64 to string
        decodedEntropyBytes = base64.b64decode(entropy)

        # shuffle key
        enc = Encryption(decodedEntropyBytes.decode())
        generatedKey = enc.shuffle().encode()

        # ensure shuffeled key did add or loss information
        assert len(decodedEntropyBytes) == len(generatedKey)

        return generatedKey
    
    def expand_key(self, data: bytes, key: bytes) -> bytes:
        """expand a key to the size of the text to be encrypted
        
        :param data: data you are going to encrypt
        :type data: bytes
        :param key: encryption key you were going to utilize to encrypt the data
        :type key: bytes, defaults to None
        :return: expanded key to utilize for encryption
        :rtype: bytes
        """
        if isinstance(key, str):
            key = key.encode()
        
        if isinstance(data, str):
            data = data.encode()

        if len(key) >= len(data):
            return key
        
        if expand_key_python is not None:
            return expand_key_python(data, key)
        else:
            return key

    def encrypt_message(self, text: str, key: bytes, algorithm: Algorithms = "OTP", recipients: List[str] = None):
        """encrypt a string

        :param text: string to encrypt
        :type text: str
        :param key: encryption key to use to encrypted text
        :type key: bytes, defaults to None
        :param algorithm: the encryption algorithm to use
        :type algorithm: Algorithms, defaults to OTP
        :return: ciphertext
        :rtype: bytes
        """
        encryptionAlgorithm = Algorithms[algorithm](key)

        if isinstance(key, str):
            key = key.encode()

        return encryptionAlgorithm.encrypt(text)

    def decrypt_message(
        self,
        encryptedText: bytes,
        key: bytes,
        algorithm: Algorithms = "OTP"
    ):
        """decrypt a previoulsy encrypted string

        :param encryptedText: encrypted text to decrypt
        :type encryptedText: bytes
        :param key: encryption key used to encrypt/decrypt
        :type key: bytes
        :param algorithm: algorithm used to encrypt/decrypt
        :type algorithm: Algorithms
        :param nonce: nonce provided from original encryption
        :type nonce: bytearray
        :return: decrypted text
        :rtype: str
        """
        if isinstance(key, str):
            key = key.encode()
        
        encryptionAlgorithm = Algorithms[algorithm](key)
        plaintext = encryptionAlgorithm.decrypt(encryptedText)
        return plaintext

    def encrypt_file(
        self, fileObj: Union[str, BinaryIO, bytes, bytearray], key: Union[bytes, str], algorithm: Algorithms = "OTP", recipients: List[str] = None, expires_hours: int = 24, out_file: Union[str, os.PathLike, BinaryIO, None] = None, chunk_size: int = 1024 * 1024
    ) -> Union[bytearray, str, None]:
        """
        Encrypt the contents of a given file/path/bytes.

        Behavior:
        - GCM/OTP: returns bytes (outer header + body). `out_file` is ignored.
        - CTR:
            * If `out_file` is provided: streams to `out_file`, returns None.
            * If `out_file` is None: returns bytes (in-memory).

        :param fileObj: path (str), file-like object, or bytes/bytearray
        :param key: encryption key (bytes or str)
        :param algorithm: "OTP", "GCM", or "CTR"
        :param recipients: who can retrieve the key packet
        :param expires_hours: packet expiry
        :param out_file: optional writable binary file-like to stream CTR output into
        :param chunk_size: chunk size for CTR streaming
        :return: encrypted payload or None (when CTR+out_file)
        """
        
        if isinstance(key, str):
            key = key.encode()

        def _basename_from(obj) -> str:
            if isinstance(obj, str):
                return os.path.basename(obj)
            name = getattr(obj, "name", None)
            return os.path.basename(name) if isinstance(name, str) and name else ""

        filename_for_header = _basename_from(fileObj) or "file"

        if algorithm == "OTP":
            key_prefix = b".B"
            scheme = 'B'
        else:
            scheme = 2 if algorithm == "CTR" else 1
            key_prefix = b".2" if scheme == 2 else b".1"

        locator_token = self.api.create_and_store_packet(
            recipients=recipients,
            key=key_prefix + key,
            type="file",
            subject=filename_for_header,
            expires_hours=expires_hours,
        )

        encryptionAlgorithm = (
            Algorithms[algorithm](key) if algorithm == "OTP"
            else Algorithms[algorithm](key, scheme=scheme)
        )
        
        def _call_encrypt(data_obj, out_handle: Union[BinaryIO, None]):
            return encryptionAlgorithm.encryptFile(
                filename_for_header,
                data_obj,
                locator_token,
                key,
                scheme,
                out_file=out_handle,
                chunk_size=chunk_size,
            )

        if isinstance(fileObj, str):
            in_handle: Union[BinaryIO, bytes, bytearray] = open(fileObj, "rb")
            close_in = True
        else:
            in_handle = fileObj
            close_in = False

        try:
            if out_file is not None:
                if algorithm == "CTR":
                    if isinstance(out_file, (str, os.PathLike)):
                        out_path = os.fspath(out_file)
                        with open(out_path, "wb") as out_fh:
                            _call_encrypt(in_handle, out_fh)  
                        return out_path
                    else:
                        _call_encrypt(in_handle, out_file)  
                        return None

                ct = _call_encrypt(in_handle, None)            
                if isinstance(out_file, (str, os.PathLike)):
                    out_path = os.fspath(out_file)
                    with open(out_path, "wb") as out_fh:
                        out_fh.write(ct)
                    return out_path
                else:
                    out_file.write(ct)
                    return None

            return _call_encrypt(in_handle, None)

        finally:
            if close_in:
                in_handle.close()

    def decrypt_file(
        self,
        encryptedText: Union[str, bytes, bytearray, BinaryIO], 
        key: Union[bytes, str, None] = None,
        algorithm: Union[str, None] = None,                    
        out_file: Union[str, os.PathLike, BinaryIO, None] = None,
        chunk_size: int = 1024 * 1024,
    ) -> Union[bytes, str, None]:
        """Decrypt a given file/path/bytes.
        - algorithm: None → infer from key prefix (.B/.1/.2)
        - out_file: path/handle → write there; else return bytes.
        """

        if isinstance(encryptedText, (str, os.PathLike)):
            full_source = os.fspath(encryptedText)
            with open(full_source, "rb") as fh:
                locator, _, _ = self.parse_file_for_decrypt(fh)
        elif hasattr(encryptedText, "read"):
            fh = encryptedText
            try:
                locator, _, _ = self.parse_file_for_decrypt(fh)
            finally:
                try:
                    fh.seek(0)
                except Exception:
                    pass
            full_source = fh 
        else:
            full_source = encryptedText
            locator, _, _ = self.parse_file_for_decrypt(full_source)

        if key is None:
            key = self.api.get_packet(locator)
        key_bytes = key.encode() if isinstance(key, str) else key

        inferred_scheme = None  
        if algorithm is None and isinstance(key_bytes, (bytes, bytearray)) and len(key_bytes) >= 2 and key_bytes[:1] == b'.':
            m = key_bytes[1:2]
            if m == b'B':
                algorithm, inferred_scheme = "OTP", 'B'
            elif m == b'1':
                algorithm, inferred_scheme = "GCM", 1
            elif m == b'2':
                algorithm, inferred_scheme = "CTR", 2

        if algorithm is None:
            raise XQException("Unable to determine algorithm from key prefix. Provide 'algorithm' or use a prefixed key (.B/.1/.2).")

        if isinstance(key_bytes, (bytes, bytearray)) and len(key_bytes) >= 2 and key_bytes[:1] == b'.':
            key_bytes = key_bytes[2:]

        if algorithm == "OTP":
            algo = Algorithms["OTP"](key_bytes)
            scheme = 'B' if inferred_scheme is None else inferred_scheme
        elif algorithm == "CTR":
            algo = Algorithms["CTR"](key_bytes, scheme=2)
            scheme = 2
        else:
            algo = Algorithms["GCM"](key_bytes, scheme=1)
            scheme = 1

        if isinstance(out_file, (str, os.PathLike)):
            out_path = os.fspath(out_file)
            with open(out_path, "wb") as fh:
                if scheme == 2:
                    if isinstance(full_source, (str, os.PathLike)):
                        with open(os.fspath(full_source), "rb") as in_fh2:
                            algo.decryptFile(in_fh2, key_bytes, out_file=fh, chunk_size=chunk_size)
                    else:
                        algo.decryptFile(full_source, key_bytes, out_file=fh, chunk_size=chunk_size)
                else:
                    if isinstance(full_source, (str, os.PathLike)):
                        with open(os.fspath(full_source), "rb") as in_fh2:
                            pt = algo.decryptFile(in_fh2, key_bytes)
                    else:
                        pt = algo.decryptFile(full_source, key_bytes)
                    if not isinstance(pt, (bytes, bytearray)):
                        pt = pt.encode("utf-8")
                    fh.write(pt)
            return out_path

        if out_file is not None and hasattr(out_file, "write"):
            if scheme == 2:
                if isinstance(full_source, (str, os.PathLike)):
                    with open(os.fspath(full_source), "rb") as in_fh2:
                        algo.decryptFile(in_fh2, key_bytes, out_file=out_file, chunk_size=chunk_size)
                else:
                    algo.decryptFile(full_source, key_bytes, out_file=out_file, chunk_size=chunk_size)
            else:
                if isinstance(full_source, (str, os.PathLike)):
                    with open(os.fspath(full_source), "rb") as in_fh2:
                        pt = algo.decryptFile(in_fh2, key_bytes)
                else:
                    pt = algo.decryptFile(full_source, key_bytes)
                if not isinstance(pt, (bytes, bytearray)):
                    pt = pt.encode("utf-8")
                out_file.write(pt)
            return None

        if isinstance(full_source, (str, os.PathLike)):
            with open(os.fspath(full_source), "rb") as f:
                src_bytes = f.read()
            pt = algo.decryptFile(src_bytes, key_bytes)
        else:
            pt = algo.decryptFile(full_source, key_bytes)

        if not isinstance(pt, (bytes, bytearray)):
            pt = pt.encode("utf-8")
        return bytes(pt)
    
    def parse_file_for_decrypt(self, input_data):
        """
        Parse the XQ outer header and return:
        (locator:str, name_encrypted:bytes, content_source)

        - If `input_data` is file-like: reads only the header, then rewinds the handle
        to position 0 and returns the same handle as `content_source`.
        - If `input_data` is bytes/bytearray: parses in-place and returns the original
        bytes as `content_source`.

        Header layout:
        [0:4]   token_size+version (LE uint32), token_size=43
        [4:47]  locator (43 bytes, utf-8)
        [..]    name_size (LE uint32)
        [..]    name_encrypted (name_size bytes)
        [..]    scheme (1 byte if version>0)
        body    starts after header
        """

        TOKEN_SIZE = 43

        def _read_exact(fh, n: int) -> bytes:
            b = fh.read(n)
            if len(b) != n:
                raise ValueError("Truncated header")
            return b

        # File-like input: read only header
        if hasattr(input_data, "read"):
            fh = input_data
            try:
                fh.seek(0)
            except Exception:
                pass

            v = struct.unpack('<I', _read_exact(fh, 4))[0]
            version = v - TOKEN_SIZE
            if version not in (0, 1):
                raise ValueError(f"Incompatible header version: {version}")

            locator = _read_exact(fh, TOKEN_SIZE).decode('utf-8')

            name_size = struct.unpack('<I', _read_exact(fh, 4))[0]
            if name_size < 0 or name_size > 2000:
                raise ValueError("Invalid filename size")

            name_encrypted = _read_exact(fh, name_size)

            if version > 0:
                # consume scheme byte so the handle ends at the start of the body
                _ = _read_exact(fh, 1)

            # Rewind so downstream (decryptor) can re-parse and/or stream
            try:
                fh.seek(0)
            except Exception:
                pass

            return locator, name_encrypted, fh

        # Bytes / bytearray input
        if isinstance(input_data, (bytes, bytearray, memoryview)):
            buf = bytes(input_data) if not isinstance(input_data, bytes) else input_data
            view = memoryview(buf)
            off = 0

            if off + 4 > len(view):
                raise ValueError("Truncated header")
            v = struct.unpack_from('<I', view, off)[0]
            off += 4
            version = v - TOKEN_SIZE
            if version not in (0, 1):
                raise ValueError(f"Incompatible header version: {version}")

            if off + TOKEN_SIZE > len(view):
                raise ValueError("Truncated locator")
            locator = view[off:off + TOKEN_SIZE].tobytes().decode('utf-8')
            off += TOKEN_SIZE

            if off + 4 > len(view):
                raise ValueError("Truncated header (filename size)")
            name_size = struct.unpack_from('<I', view, off)[0]
            off += 4
            if name_size < 0 or name_size > 2000:
                raise ValueError("Invalid filename size")

            if off + name_size > len(view):
                raise ValueError("Truncated header (filename)")
            name_encrypted = view[off:off + name_size].tobytes()
            off += name_size

            if version > 0:
                if off + 1 > len(view):
                    raise ValueError("Truncated header (scheme)")
                # scheme_byte = view[off]  # available if you choose to return it
                off += 1

            # Return the original bytes as the "content source"
            return locator, name_encrypted, buf

        raise TypeError("Input must be a file-like object or bytes-like buffer")
