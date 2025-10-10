import os
import warnings
from typing import TextIO, BinaryIO, Union
from io import StringIO, BytesIO, TextIOWrapper, BufferedReader
from pathlib import PosixPath
from xq.algorithms import Encryption

try:
    from xq.algorithms.xor import xor_simd_neon_python
except ImportError:
    xor_simd_neon_python = None

class OTPEncryption(Encryption):
    """OTP implimented encryption algorithm

    :param Encryption: Inherited Parent class
    :type Encryption: Encryption class
    """

    def __init__(self, key: bytes, max_encryption_chunk_size=2048):
        """Initialize OTPEncryption class with an encryption key

        :param key: encryption key
        :type key: bytes
        :param max_encryption_chunk_size: the maximum byte chunk for encryption, defaults to 2048
        :type max_encryption_chunk_size: int, optional
        """
        self.max_encryption_chunk_size = max_encryption_chunk_size
        Encryption.__init__(self, key)

    def encrypt(self, msg: bytes, password: bytes = None):
        """encryption method for encrypting a bytes-string or bytes-file

        :param msg: message to encrypt
        :type msg: bytes OR FileLike
        :raises SDKEncryptionException: unsupported message type
        :return: encrypted message
        :rtype: bytes
        """
        if password is None:
            password = self.key

        if isinstance(msg, str):
            # string support
            warnings.warn(
                "A string was submitted for encryption, the decrypted result will be UTF-8 bytes!"
            )
            text = msg.encode()
        elif isinstance(msg, TextIO) or isinstance(msg, StringIO):
            # string file
            warnings.warn(
                "A string file was submitted for encryption, the decrypted result will be UTF-8 bytes!"
            )
            text = msg.getvalue().encode()
        elif isinstance(msg, BinaryIO) or isinstance(msg, BytesIO):
            # binary file
            text = msg.getvalue()
        elif isinstance(msg, PosixPath):
            # unix file
            text = msg.open("rb").read()
        elif isinstance(msg, TextIOWrapper):
            # text io
            warnings.warn(
                "A TextIO file was submitted for encryption, the decrypted result will be UTF-8 bytes!"
            )
            text = msg.read().encode()
        elif isinstance(msg, bytes):
            text = msg
        elif isinstance(msg, BufferedReader):
            # bytes file handle
            text = msg.read()
        else:
            # raise SDKEncryptionException(f"Message type {type(msg)} is not supported!")
            warnings.warn(
                f"Message type {type(msg)} is not officially supported, but trying anyway"
            )
            text = msg
        if xor_simd_neon_python is not None:
            # if len(text) > len(self.key):
            #     warnings.warn(
            #         f"Message length ({len(text)}) exceeds key length ({len(self.key)}). For enhanced security, consider expanding the key using the `expand_key` function."
            #     )
            return xor_simd_neon_python(text, password)
        else:
            return
    
    def encrypt_file_streaming(
        self,
        file: Union[BinaryIO, BufferedReader, BytesIO, bytes, bytearray, str, os.PathLike],
        password: Union[str, bytes],
        header: bytes,
        out_file: Union[BinaryIO, None] = None,
        chunk_size: int = 1024 * 1024,
    ):
        """
        Stream encrypt a file using OTP (XOR) encryption.
        Reads file in chunks to avoid loading entire file into memory.
        
        :param file: File object to encrypt
        :param password: Encryption password
        :param header: File header to prepend
        :return: Encrypted file as bytes
        """
        if isinstance(password, str):
            password = password.encode("utf-8")
        key_len = len(password) or 1  

        must_close = False
        if hasattr(file, "read"):
            fh = file
        elif isinstance(file, (str, os.PathLike)):
            fh = open(os.fspath(file), "rb")
            must_close = True
        elif isinstance(file, (bytes, bytearray)):
            fh = BytesIO(bytes(file))
        else:
            fh = BytesIO(bytes(file))

        try:
            chunks = [] if out_file is None else None
            def write(buf: bytes):
                if out_file is None:
                    chunks.append(buf)
                else:
                    out_file.write(buf)

            write(header)

            key_off = 0
            while True:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                if hasattr(self, "encrypt_chunk"):
                    enc_chunk = self.encrypt_chunk(chunk, password, key_off)
                else:
                    enc_chunk = self.encrypt(chunk, password)
                write(enc_chunk)
                key_off = (key_off + len(chunk)) % key_len

            if out_file is not None:
                return None
            return b"".join(chunks)
        finally:
            if must_close:
                fh.close()
    
    def _stream_encrypt_file_handle(
        self, 
        file_handle, 
        password: bytes, 
        encrypted_chunks: list, 
        key_offset: int,
        chunk_size: int
    ):
        """
        Internal method to handle the actual streaming encryption.
        
        :param file_handle: File handle to read from
        :param password: Encryption password (bytes)
        :param encrypted_chunks: List to accumulate encrypted chunks
        :param key_offset: Current offset in the password key
        :param chunk_size: Size of chunks to read
        :return: Final encrypted bytes
        """
        while True:
            chunk = file_handle.read(chunk_size)
            if not chunk:
                break
            
            encrypted_chunk = self.encrypt_chunk(chunk, password, key_offset)
            encrypted_chunks.append(encrypted_chunk)
            
            key_offset = (key_offset + len(chunk)) % len(password)
        
        return b''.join(encrypted_chunks)
        
    def encrypt_chunk(
        self, 
        chunk: bytes, 
        password: bytes, 
        key_offset: int
    ) -> bytes:
        """
        Encrypt a single chunk using XOR with password at given offset.
        
        :param chunk: Data chunk to encrypt
        :param password: Encryption password
        :param key_offset: Current offset in the password key
        :return: Encrypted chunk as bytes
        """
        payload_bytes = bytes(chunk)
        encrypted = bytearray(len(payload_bytes))
        
        # Create a cyclic key buffer for this chunk
        key_buffer = bytearray(len(payload_bytes))
        for idx in range(len(payload_bytes)):
            key_idx = (key_offset + idx) % len(password)
            key_buffer[idx] = password[key_idx]
        
        # Use SIMD if available, otherwise fall back to pure Python XOR
        if xor_simd_neon_python is not None:
            return xor_simd_neon_python(payload_bytes, bytes(key_buffer))
        else:
            # Pure Python XOR fallback
            for idx in range(len(payload_bytes)):
                encrypted[idx] = payload_bytes[idx] ^ key_buffer[idx]
            return bytes(encrypted)
    
    def decrypt_file_streaming(
        self, 
        file: Union[BinaryIO, BufferedReader, BytesIO], 
        password: Union[str, bytes]
    ):
        """
        Stream decrypt a file using OTP (XOR) encryption.
        Reads file in chunks to avoid loading entire file into memory.
        
        :param file: File object to decrypt (must have header)
        :param password: Decryption password
        :return: Decrypted file as bytes
        """
        CHUNK_SIZE = 1024 * 1024  # 1MB chunks
        
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        if isinstance(file, (bytes, bytearray)):
            file = BytesIO(file)
        
        # Handle password prefix (remove '.' prefix if present)
        if password[0] == ord('.'):
            password = password[2:]
        
        # Read and parse header first
        initial_read = file.read(4096)
        if len(initial_read) < 52:  # Minimum header size
            raise ValueError("File too small to contain valid header")
        
        header = self.get_file_header(initial_read, 1)
        header_length = header["length"]
        
        remaining_initial = initial_read[header_length:]
        
        decrypted_chunks = []
        key_offset = 0
        
        # Decrypt the remaining initial data first
        if remaining_initial:
            decrypted_chunk = self.decrypt_chunk(remaining_initial, password, key_offset)
            decrypted_chunks.append(decrypted_chunk)
            key_offset = (key_offset + len(remaining_initial)) % len(password)
        
        # Continue reading and decrypting in chunks
        while True:
            chunk = file.read(CHUNK_SIZE)
            if not chunk:
                break
            
            decrypted_chunk = self.decrypt_chunk(chunk, password, key_offset)
            decrypted_chunks.append(decrypted_chunk)
            
            key_offset = (key_offset + len(chunk)) % len(password)
        
        # Combine all chunks into final result
        return b''.join(decrypted_chunks)
    
    def decrypt_chunk(
        self, 
        chunk: bytes, 
        password: bytes, 
        key_offset: int
    ):
        """
        Decrypt a single chunk using XOR with password at given offset.
        Since XOR is symmetric, this is identical to encrypt_chunk.
        
        :param chunk: Data chunk to decrypt
        :param password: Decryption password
        :param key_offset: Current offset in the password key
        :return: Decrypted chunk as bytes
        """
        payload_bytes = bytes(chunk)
        decrypted = bytearray(len(payload_bytes))
        
        # Create a cyclic key buffer for this chunk
        key_buffer = bytearray(len(payload_bytes))
        for idx in range(len(payload_bytes)):
            key_idx = (key_offset + idx) % len(password)
            key_buffer[idx] = password[key_idx]
        
        # Use SIMD if available, otherwise fall back to pure Python XOR
        if xor_simd_neon_python is not None:
            return xor_simd_neon_python(payload_bytes, bytes(key_buffer))
        else:
            # Pure Python XOR fallback (XOR is symmetric)
            for idx in range(len(payload_bytes)):
                decrypted[idx] = payload_bytes[idx] ^ key_buffer[idx]
            return bytes(decrypted)

    def decrypt(self, text: bytes, password: bytes = None) -> bytes:
        """decryption method for decrypting a string or file

        :param text: text to decrypt
        :type text: bytes
        :return: decrypted text
        :rtype: bytes
        """
        if password is None:
            password = self.key
        
        if isinstance(text, bytearray):
            text = bytes(text)  

        if xor_simd_neon_python is not None: 
            return xor_simd_neon_python(text, password)
        else:
            return
