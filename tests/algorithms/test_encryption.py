import io
import struct
import pytest

from xq.algorithms.encryption import Encryption

# ---- Dummy reversible algorithm to exercise base class ----------------------
class DummyEnc(Encryption):
    """Minimal reversible XOR 'cipher' so we can drive base-class code paths."""

    def __init__(self, key: bytes | str):
        super().__init__(key)
        self.scheme = 1

    @staticmethod
    def _xor(data: bytes) -> bytes:
        b = bytes(data)
        return bytes((x ^ 0xAA) for x in b)

    def encrypt(self, data, password=None, header=None, chunk_size=1024 * 1024, out_file=None):
        if hasattr(data, "read"):
            data = data.read()
        if isinstance(data, str):
            data = data.encode()
        out = self._xor(data)
        if out_file is not None:
            out_file.write(out)
            return None
        return out

    def decrypt(self, data, password=None, chunk_size=1024 * 1024, out_file=None):
        if hasattr(data, "read"):
            data = data.read()
        out = self._xor(data)  # XOR is symmetric
        if out_file is not None:
            out_file.write(out)
            return None
        return out  

    def encrypt_file_streaming(self, file, password, header: bytes, out_file=None, chunk_size=1024 * 1024):
        """Used when scheme == 'B' in Encryption.encryptFile."""
        def to_fh(x):
            if hasattr(x, "read"):
                return x
            if isinstance(x, (bytes, bytearray)):
                return io.BytesIO(bytes(x))
            if isinstance(x, str):
                return io.BytesIO(x.encode())
            return io.BytesIO(bytes(x))

        fh = to_fh(file)
        if out_file is None:
            chunks = [header]
            while True:
                ch = fh.read(chunk_size)
                if not ch:
                    break
                chunks.append(self._xor(ch))
            return b"".join(chunks)
        else:
            out_file.write(header)
            while True:
                ch = fh.read(chunk_size)
                if not ch:
                    break
                out_file.write(self._xor(ch))
            return None

# ---- Fixtures ---------------------------------------------------------------

@pytest.fixture
def token43():
    return "T" * 43  

@pytest.fixture
def filename_utf8():
    return "myfile.name.txt"

@pytest.fixture
def payload_bytes():
    return b"The quick brown fox jumps over the lazy dog"

# ---- Tests ------------------------------------------------------------------

def test_encryption_constructs_with_bytes_key():
    enc = Encryption(b"yesthisissixteen")
    assert enc.key == b"yesthisissixteen"

def test_encryption_constructs_with_str_key():
    enc = Encryption("string-key")
    assert enc.key == b"string-key"

def test_shuffle_preserves_length_for_bytes_key():
    enc = Encryption(b"abcdef")
    shuffled = enc.shuffle() 
    assert isinstance(shuffled, str)
    assert len(shuffled) == len(enc.key)

def test_shuffle_on_string_argument():
    enc = Encryption(b"irrelevant")
    s = "helloworld"
    shuffled = enc.shuffle(s)
    assert isinstance(shuffled, str)
    assert len(shuffled) == len(s)

def test_create_file_header_layout(token43, filename_utf8):
    enc = Encryption(b"k")
    buf = enc.create_file_header(filename_utf8.encode("utf-8"), token43, scheme=2, version=1)

    token_size_plus_version = struct.unpack_from("<I", buf, 0)[0]
    version = token_size_plus_version - 43
    assert version == 1

    token = bytes(buf[4 : 4 + 43])
    assert token == token43.encode("utf-8")

    name_len = struct.unpack_from("<I", buf, 4 + 43)[0]
    assert name_len == len(filename_utf8.encode("utf-8"))

    name_start = 4 + 43 + 4
    name = bytes(buf[name_start : name_start + name_len])
    assert name == filename_utf8.encode("utf-8")

    scheme_byte = buf[name_start + name_len]
    assert scheme_byte == 2  

def test_encrypt_decrypt_gcm_inmemory(token43, filename_utf8, payload_bytes):
    d = DummyEnc(b"secret")
    d.scheme = 1 
    out = d.encryptFile(filename_utf8, payload_bytes, token43, password=b"pw", scheme=1)

    pt = d.decryptFile(out, password=b"pw")
    assert pt == payload_bytes

def test_encrypt_decrypt_ctr_streaming(token43, filename_utf8, payload_bytes, tmp_path):
    d = DummyEnc(b"secret")
    d.scheme = 2  

    enc_path = tmp_path / "enc.bin"
    with open(enc_path, "wb") as f:
        ret = d.encryptFile(filename_utf8, io.BytesIO(payload_bytes), token43, password=b"pw", scheme=2, out_file=f)
        assert ret is None  

    with open(enc_path, "rb") as f:
        pt = d.decryptFile(f, password=b"pw")
        assert pt == payload_bytes

def test_encrypt_decrypt_ctr_inmemory(token43, filename_utf8, payload_bytes):
    d = DummyEnc(b"secret")
    d.scheme = 2
    combined = d.encryptFile(filename_utf8, payload_bytes, token43, password=b"pw", scheme=2)
    pt = d.decryptFile(combined, password=b"pw")
    assert pt == payload_bytes

def test_encrypt_decrypt_otp_streaming_returns_bytes(token43, filename_utf8, payload_bytes):
    d = DummyEnc(b"secret")
    combined = d.encryptFile(filename_utf8, payload_bytes, token43, password=b"pw", scheme="B")
    pt = d.decryptFile(combined, password=b"pw")
    assert pt == payload_bytes

def test_decryptFile_strips_dotB_prefix(token43, filename_utf8, payload_bytes):
    d = DummyEnc(b"secret")
    combined = d.encryptFile(filename_utf8, payload_bytes, token43, password=b"pw", scheme=1)
    pt = d.decryptFile(combined, password=b".Bpw")
    assert pt == payload_bytes

def test_decryptFile_incompatible_header_version_raises(token43, filename_utf8, payload_bytes):
    enc = Encryption(b"k")
    header = enc.create_file_header(filename_utf8.encode(), token43, scheme=1, version=1)
    bad = bytearray(header)
    struct.pack_into("<I", bad, 0, 43 + 7)  
    buf = bytes(bad) + b"body" 
    with pytest.raises(ValueError, match="Incompatible header version"):
        enc.decryptFile(buf, password=b"pw")

def test_decryptFile_invalid_filename_size_raises(token43):
    enc = Encryption(b"k")
    token_size = 43
    version = 1
    name_size = 5000  
    buf = bytearray(4 + token_size + 4)
    struct.pack_into("<I", buf, 0, token_size + version)
    buf[4 : 4 + token_size] = b"T" * token_size
    struct.pack_into("<I", buf, 4 + token_size, name_size)
    with pytest.raises(ValueError, match="Invalid filename size"):
        enc.decryptFile(bytes(buf), password=b"pw")

def test_decryptFile_truncated_header_raises_in_stream_mode():
    enc = Encryption(b"k")
    f = io.BytesIO(b"\x00\x00\x00")
    with pytest.raises(ValueError, match="Truncated header"):
        enc.decryptFile(f, password=b"pw")
