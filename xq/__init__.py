import os
import base64
import struct
from typing import List, BinaryIO, Union
from ._version import get_versions
from xq.config import API_KEY, XQ_LOCATOR_KEY
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
    # Class-level constants for encryption algorithms
    TOKEN_SIZE = 43

    ALGORITHM_CONFIG = {
        "OTP": {"prefix": b".B", "scheme": ord('B')},
        "GCM": {"prefix": b".1", "scheme": 1},
        "CTR": {"prefix": b".2", "scheme": 2}
    }

    PREFIX_TO_ALGORITHM = {
        b'B': "OTP",
        b'1': "GCM",
        b'2': "CTR"
    }

    SCHEME_TO_ALGORITHM = {
        ord('B'): "OTP",
        1: "GCM",
        2: "CTR"
    }

    def __init__(self, api_key=API_KEY, locator_key=XQ_LOCATOR_KEY):
        """initializes the XQ SDK with API keys, in priority order:
            1. params
            2. ENV
            3. .env file

        :param api_key: _description_, defaults to ENV value
        :type api_key: _type_, optional
        :param locator_key: _description_, defaults to ENV value
        :type locator_key: _type_, optional
        """
        self.api = XQAPI(api_key, locator_key)  # bind api functions as methods

    def generate_key_from_entropy(self) -> bytes:
        """helper method for automatically requesting entropy and shuffling key

        :return: generated encryption key from entropy
        :rtype: bytes
        """

        # get XQ entropy
        entropy = self.api.get_entropy(length=64, type="hex8")

        #convert array to string
        entropyString = "".join(entropy)


        # shuffle key
        enc = Encryption(entropyString)
        generatedKey = enc.shuffle().encode()

        # ensure shuffeled key did add or loss information
        assert len(entropyString) == len(generatedKey)

        return generatedKey

    def generate_multiple_keys_and_store_packets(
            self,
            count: int = 1,
            algorithm: Algorithms = "OTP",
            recipients: List[str] = None,
            subject: str = "message",
            expires_period: int = 24,
            time_unit: str = "h",
            packet_type: Union[int, str] = "Email",
            meta: str = None,
            key_size_bits: int = 128
    ) -> List[dict]:
        """generate multiple encryption keys from entropy and store them as packets

        :param count: number of keys to generate
        :type count: int
        :param algorithm: the encryption algorithm to use, defaults to OTP
        :type algorithm: Algorithms, optional
        :param recipients: list of recipients who can retrieve the keys, defaults to None
        :type recipients: List[str], optional
        :param subject: subject/description for the key packets, defaults to "message"
        :type subject: str, optional
        :param expires_period: packet validation time in hours, defaults to 24
        :type expires_period: int, optional
        :param time_unit: packet validation expires period time unit, defaults to h
        :type time_unit: str, h d m s
        :param packet_type: packet type, defaults to "msg"
        :type packet_type: int | str, optional
        :param meta: additional metadata for the packets, defaults to None
        :type meta: str, optional
        :return: list of dicts containing key and locator_token pairs
        :rtype: List[dict]
        """
        if count < 1:
            raise XQException("Count must be at least 1")

        config = self.ALGORITHM_CONFIG.get(algorithm)
        if not config:
            raise XQException(f"Unknown algorithm: {algorithm}")

        key_prefix = config["prefix"]

        # Request entropy in batches if needed
        keys = []
        remaining_keys = count

        while remaining_keys > 0:
            # Calculate entropy for this batch (max 8192 bits)
            keys_in_batch = min(remaining_keys, 8192 // key_size_bits)
            entropy_bits = keys_in_batch * key_size_bits

            # get XQ entropy
            entropy = self.api.get_entropy(length=entropy_bits, type="hex8")

            #convert array to string
            entropyString = "".join(entropy)

            # shuffle key
            enc = Encryption(entropyString)
            shuffled_entropy = enc.shuffle().encode()

            # Split shuffled entropy into chunks to create individual keys
            chunk_size = (key_size_bits // 8) * 2

            for i in range(keys_in_batch):
                # Extract chunk for this key from shuffled entropy
                start_idx = i * chunk_size
                end_idx = start_idx + chunk_size
                key_chunk = shuffled_entropy[start_idx:end_idx]
                keys.append(key_prefix + key_chunk)

            remaining_keys -= keys_in_batch

        # Store all packets at once
        response = self.api.create_and_store_packets(
            recipients=recipients,
            keys=keys,
            type=packet_type,
            subject=subject,
            expires_period=expires_period,
            time_unit=time_unit,
            meta=meta
        )

        if not isinstance(response, dict):
            raise XQException(f"Expected dict response but got {response.__class__.__name__}")

        tokens = response.get('tokens', [])

        if len(tokens) != len(keys):
            raise XQException(f"Expected {len(keys)} tokens but got {len(tokens)}")

        return tokens

    def generate_multiple_keys_and_store_packets_database(
            self,
            count: int = 1,
            algorithm: Algorithms = "OTP",
            recipients: List[str] = None,
            metadata_list: list = None,
            expires_period: int = 24,
            time_unit: str = "h",
            type: str = "Database",
            key_size_bits: int = 128
    ) -> List[dict]:
        """generate multiple encryption keys from entropy and store them as batch packets with metadata

        :param count: number of keys to generate
        :type count: int
        :param algorithm: the encryption algorithm to use, defaults to OTP
        :type algorithm: Algorithms, optional
        :param recipients: list of recipients who can retrieve the keys, defaults to None
        :type recipients: List[str], optional
        :param metadata_list: list of metadata dicts with title and labels for each key, defaults to None
        :type metadata_list: list, optional
        :param expires_period: packet validation time in hours, defaults to 24
        :type expires_period: int, optional
        :param time_unit: packet validation expires period time unit, defaults to h
        :type time_unit: str, h d m s
        :param type: packet type (applies to all entries), defaults to "database"
        :type type: str, optional
        :param key_size_bits: size of each key in bits, defaults to 128
        :type key_size_bits: int, optional
        :return: list of dicts containing key and locator_token pairs
        :rtype: List[dict]
        """
        if count < 1:
            raise XQException("Count must be at least 1")

        if metadata_list and len(metadata_list) != count:
            raise XQException(f"metadata_list length ({len(metadata_list)}) must match count ({count})")

        config = self.ALGORITHM_CONFIG.get(algorithm)
        if not config:
            raise XQException(f"Unknown algorithm: {algorithm}")

        key_prefix = config["prefix"]

        # Request entropy in batches if needed
        keys = []
        remaining_keys = count

        while remaining_keys > 0:
            # Calculate entropy for this batch (max 8192 bits)
            keys_in_batch = min(remaining_keys, 8192 // key_size_bits)
            entropy_bits = keys_in_batch * key_size_bits

            # get XQ entropy
            entropy = self.api.get_entropy(length=entropy_bits, type="hex8")

            #convert array to string
            entropyString = "".join(entropy)

            enc = Encryption(entropyString)
            shuffled_entropy = enc.shuffle().encode()

            # Calculate chunk size in hex characters
            chunk_size = (key_size_bits // 8) * 2

            for i in range(keys_in_batch):
                # Extract chunk for this key from shuffled entropy
                start_idx = i * chunk_size
                end_idx = start_idx + chunk_size
                key_chunk = shuffled_entropy[start_idx:end_idx]
                keys.append(key_prefix + key_chunk)

            remaining_keys -= keys_in_batch

        # Store all packets at once using batch endpoint
        response = self.api.create_and_store_packets_batch(
            keys=keys,
            recipients=recipients,
            metadata_list=metadata_list,
            expires_period=expires_period,
            time_unit=time_unit,
            type=type
        )

        if not isinstance(response, list):
            raise XQException(f"Expected list response but got {response.__class__.__name__}")

        if len(response) != len(keys):
            raise XQException(f"Expected {len(keys)} tokens but got {len(response)}")

        return response


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


    def _parse_key_and_scheme(self, key_with_prefix: bytes, scheme_byte: int):
        """parse key prefix to determine algorithm, fallback to scheme byte if no prefix

        :param key_with_prefix: key data potentially with prefix
        :type key_with_prefix: bytes
        :param scheme_byte: scheme byte from message header (fallback if no prefix)
        :type scheme_byte: int
        :return: tuple of (algorithm_name, raw_key)
        :rtype: tuple[str, bytes]
        """
        # Check for prefix format (authoritative source)
        if len(key_with_prefix) >= 2 and key_with_prefix[:1] == b'.':
            prefix_char = key_with_prefix[1:2]

            algorithm = self.PREFIX_TO_ALGORITHM.get(prefix_char)
            if not algorithm:
                raise XQException(f"Unknown key prefix: .{chr(prefix_char[0])}")

            return algorithm, key_with_prefix[2:]

        # No prefix - use scheme byte as fallback
        algorithm = self.SCHEME_TO_ALGORITHM.get(scheme_byte)
        if not algorithm:
            raise XQException(f"Unknown scheme byte: {scheme_byte}")

        return algorithm, key_with_prefix

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
        """decrypt a previously encrypted string

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

    def encrypt_auto(
                self,
                text: str,
                algorithm: Algorithms = "OTP",
                recipients: List[str] = None,
                subject: str = "message",
                expires_hours: int = 24,
                version: int = 1,
                key: bytes = None,
                locator_token: str = None,
                type: str = "Email"
        ) -> bytes:
            """encrypt a string with auto-generated or provided key and store the key packet
            :param text: string to encrypt
            :type text: str
            :param algorithm: the encryption algorithm to use, defaults to OTP
            :type algorithm: Algorithms, optional
            :param recipients: list of recipients who can retrieve the key, defaults to ["team@group.local"]
            :type recipients: List[str], optional
            :param subject: subject/description for the encrypted message, defaults to "message"
            :type subject: str, optional
            :param expires_hours: hours until key packet expires, defaults to 24
            :type expires_hours: int, optional
            :param version: message format version, defaults to 1
            :type version: int, optional
            :param key: encryption key to use (without prefix), if None will auto-generate, defaults to None
            :type key: bytes, optional
            :param locator_token: pre-existing locator token, if None will create and store packet, defaults to None
            :type locator_token: str, optional
            :param type: packet type for the stored key, defaults to "Email"
            :type type: str, optional
            :return: formatted message: (token_size+version) + locator_token + scheme + ciphertext
            :rtype: bytes
            """

            if recipients is None:
                recipients = ["team@group.local"]

            # Use provided key or generate new one
            if key is None:
                # No key provided - use specified algorithm
                config = self.ALGORITHM_CONFIG.get(algorithm)
                if not config:
                    raise XQException(f"Unknown algorithm: {algorithm}")

                key_prefix = config["prefix"]
                scheme_byte = config["scheme"]
                key = self.generate_key_from_entropy()
            else:
                # Key provided - convert to bytes and check for prefix
                if isinstance(key, str):
                    key = key.encode()

                # Detect algorithm from key prefix if present
                if len(key) >= 2 and key[:1] == b'.':
                    prefix_char = key[1:2]
                    detected_algorithm = self.PREFIX_TO_ALGORITHM.get(prefix_char)

                    if detected_algorithm:
                        algorithm = detected_algorithm
                        key = key[2:]
                    else:
                        raise XQException(f"Unknown key prefix: .{chr(prefix_char[0])}")

                # Get config for the algorithm (either from prefix or parameter)
                config = self.ALGORITHM_CONFIG.get(algorithm)
                if not config:
                    raise XQException(f"Unknown algorithm: {algorithm}")

                key_prefix = config["prefix"]
                scheme_byte = config["scheme"]

            encryptionAlgorithm = Algorithms[algorithm](key)

            # Use provided locator token or create new one
            if locator_token is None:
                locator_token = self.api.create_and_store_packet(
                    recipients=recipients,
                    key=key_prefix + key,
                    type=type,
                    subject=subject,
                    expires_period=expires_hours,
                )

            locator_bytes = locator_token.encode('utf-8')
            if len(locator_bytes) != self.TOKEN_SIZE:
                raise XQException(f"Locator token must be {self.TOKEN_SIZE} bytes, got {len(locator_bytes)}")

            ciphertext = encryptionAlgorithm.encrypt(text)

            return struct.pack(
                f'<I{self.TOKEN_SIZE}sB',
                self.TOKEN_SIZE + version,
                locator_bytes,
                scheme_byte
            ) + ciphertext

    def decrypt_auto(self, encrypted_message: bytes, key: bytes = None) -> bytes:
        """decrypt a message encrypted with encrypt_auto by parsing the header and retrieving or using provided key

        :param encrypted_message: formatted message from encrypt_auto (raw bytes or base64 string)
        :type encrypted_message: bytes or str
        :param key: encryption key to use (with or without prefix), if None will retrieve from packet, defaults to None
        :type key: bytes, optional
        :return: decrypted plaintext message
        :rtype: bytes
        """
        # Auto-detect and decode base64 if input is a string
        if isinstance(encrypted_message, str):
            encrypted_message = base64.b64decode(encrypted_message)

        view = memoryview(encrypted_message)

        min_length = 4 + self.TOKEN_SIZE + 1
        if len(view) < min_length:
            raise XQException(f"Message too short: {len(view)} bytes, need at least {min_length}")

        # Unpack header in one operation
        header_format = f'<I{self.TOKEN_SIZE}sB'
        header_size = struct.calcsize(header_format)
        token_size_with_version, locator_bytes, scheme_byte = struct.unpack_from(header_format, view)

        version = token_size_with_version - self.TOKEN_SIZE
        if version not in (0, 1):
            raise XQException(f"Incompatible message version: {version}")

        # Extract locator token and ciphertext
        locator_token = locator_bytes.decode('utf-8')
        ciphertext = view[header_size:].tobytes()

        # Use provided key or retrieve from packet
        if key is None:
            key_with_prefix = self.api.get_packet(locator_token)
            if isinstance(key_with_prefix, str):
                key_with_prefix = key_with_prefix.encode()
            algorithm, key = self._parse_key_and_scheme(key_with_prefix, scheme_byte)
        else:
            # Key provided - check if it has prefix or use scheme byte
            if isinstance(key, str):
                key = key.encode()
            algorithm, key = self._parse_key_and_scheme(key, scheme_byte)

        encryptionAlgorithm = Algorithms[algorithm](key)
        return encryptionAlgorithm.decrypt(ciphertext)



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

        # Get algorithm configuration
        config = self.ALGORITHM_CONFIG.get(algorithm)
        if not config:
            raise XQException(f"Unknown algorithm: {algorithm}")

        key_prefix = config["prefix"]
        scheme = config["scheme"]

        locator_token = self.api.create_and_store_packet(
            recipients=recipients,
            key=key_prefix + key,
            type="File",
            subject=filename_for_header,
            expires_period=expires_hours,
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
