import io
import os
import base64
import pytest

from xq import XQ
import xq 
from xq.exceptions import XQException

# ---------------------- Dummy reversible algorithm ---------------------------

class DummyAlgo:
    """Minimal reversible algo with the interface XQ expects."""

    def __init__(self, key: bytes, scheme: int | str = 1):
        self.key = key if isinstance(key, (bytes, bytearray)) else str(key).encode()
        self.scheme = scheme

    @staticmethod
    def _xor(b: bytes) -> bytes:
        b = bytes(b)
        return bytes(ch ^ 0x5A for ch in b)  
    
    def encrypt(self, text):
        if hasattr(text, "read"):
            text = text.read()
        if isinstance(text, str):
            text = text.encode()
        return self._xor(text)

    def decrypt(self, data):
        if hasattr(data, "read"):
            data = data.read()
        return self._xor(data)

    def encryptFile(self, filename, data, token, password, scheme, out_file=None, chunk_size=1024*1024):
        token_43 = (token if isinstance(token, str) else token.decode()).ljust(43, "x")[:43].encode()
        name_bytes = (filename or "file").encode()
        version = 1
        header = bytearray(4 + 43 + 4 + len(name_bytes) + 1)
        header[0:4] = (43 + version).to_bytes(4, "little")
        header[4:4+43] = token_43
        off = 4 + 43
        header[off:off+4] = len(name_bytes).to_bytes(4, "little")
        off += 4
        header[off:off+len(name_bytes)] = name_bytes
        off += len(name_bytes)
        header[off:off+1] = (scheme if isinstance(scheme, int) else ord(scheme)).to_bytes(1, "little")

        if hasattr(data, "read"):
            body = data.read()
        elif isinstance(data, str):
            body = data.encode()
        else:
            body = bytes(data)

        enc_body = self._xor(body)

        if scheme == 2 and out_file is not None:
            out_file.write(header)
            view = memoryview(enc_body)
            for i in range(0, len(view), chunk_size):
                out_file.write(view[i:i+chunk_size])
            return None

        return bytes(header) + enc_body

    def decryptFile(self, blob, password, out_file=None, chunk_size=1024*1024):
        if hasattr(blob, "read"):
            data = blob.read()
        else:
            data = bytes(blob)

        v = int.from_bytes(data[0:4], "little") 
        token_size = 43
        version = v - token_size
        assert version in (0, 1)
        off = 4 + token_size
        name_len = int.from_bytes(data[off:off+4], "little")
        off += 4 + name_len
        if version > 0:
            off += 1 
        body = data[off:]

        pt = self._xor(body)
        if out_file is not None:
            out_file.write(pt)
            return None
        return pt


# ------------------------------ Autouse patches ------------------------------

@pytest.fixture(autouse=True)
def patch_xqapi_constructor(monkeypatch):
    """Replace the XQAPI class that XQ() instantiates with a no-op dummy."""
    class DummyAPI:
        def __init__(self, api_key, dashboard_api_key, locator_key):
            self.api_key = api_key
            self.dashboard_api_key = dashboard_api_key
            self.locator_key = locator_key

        def create_and_store_packet(self, recipients, key, type, subject, expires_hours):
            return "L" * 43

        def get_packet(self, locator):
            return b".1dummykey"

        def get_entropy(self, entropy_bits=128):
            return base64.b64encode(b"A" * 16).decode()

    monkeypatch.setattr(xq, "XQAPI", DummyAPI, raising=True)
    yield

@pytest.fixture(autouse=True)
def patch_algorithms(monkeypatch):
    """
    Replace Algorithms mapping so 'OTP', 'GCM', 'CTR' all use DummyAlgo.
    Patch BOTH the module where it's defined and the name imported into xq.
    """
    dummy_map = {"OTP": DummyAlgo, "GCM": DummyAlgo, "CTR": DummyAlgo}
    monkeypatch.setattr(xq.algorithms, "Algorithms", dummy_map, raising=True)
    monkeypatch.setattr(xq, "Algorithms", dummy_map, raising=True)
    yield

# ------------------------------ SDK fixture ----------------------------------

@pytest.fixture
def xqsdk():
    return XQ(api_key="k", dashboard_api_key="d", locator_key="l")


# ------------------------------- Tests ---------------------------------------

def test_init_no_validation_runs():
    x = XQ(api_key="a", dashboard_api_key="b", locator_key="c")
    assert hasattr(x, "api")

def test_generate_key_from_entropy_length(xqsdk):
    key = xqsdk.generate_key_from_entropy()
    assert isinstance(key, (bytes, bytearray))
    assert len(key) == 16   

def test_expand_key_fallback_returns_key_when_shorter(xqsdk):
    data = b"abc"
    key = b"abcdef"
    assert xqsdk.expand_key(data, key) == key

def test_encrypt_decrypt_message(xqsdk):
    ct = xqsdk.encrypt_message("hello", key=b"k", algorithm="GCM")
    pt = xqsdk.decrypt_message(ct, key=b"k", algorithm="GCM")
    assert pt == b"hello"

def test_encrypt_decrypt_message_with_str_key(xqsdk):
    ct = xqsdk.encrypt_message("hello", key="k", algorithm="GCM")
    pt = xqsdk.decrypt_message(ct, key="k", algorithm="GCM")
    assert pt == b"hello"

def test_parse_file_for_decrypt_bytes_path(xqsdk):
    payload = b"pfd-bytes"
    blob = xqsdk.encrypt_file(payload, key=b"k", algorithm="GCM")
    locator, name_enc, content = xqsdk.parse_file_for_decrypt(blob)  
    assert isinstance(locator, str) and len(locator) == 43
    assert isinstance(name_enc, (bytes, bytearray))
    assert isinstance(content, (bytes, bytearray))

def test_encrypt_file_gcm_inmemory_and_decrypt(xqsdk):
    payload = b"file-bytes"
    out = xqsdk.encrypt_file(payload, key=b"k", algorithm="GCM")
    pt = xqsdk.decrypt_file(out, key=b".1k", algorithm=None)
    assert pt == payload

def test_encrypt_file_with_path_input_and_outfile_non_ctr(xqsdk, tmp_path):
    src = tmp_path / "src.bin"
    src.write_bytes(b"PAYLOAD")
    out_path = tmp_path / "wrapped.bin"

    written = xqsdk.encrypt_file(str(src), key=b"k", algorithm="GCM", out_file=str(out_path))
    assert written == str(out_path)
    assert out_path.exists() and out_path.stat().st_size > 0

    blob = out_path.read_bytes()
    pt = xqsdk.decrypt_file(blob, key=b".1k", algorithm=None)
    assert pt == b"PAYLOAD"

def test_encrypt_file_ctr_inmemory_returns_bytes(xqsdk):
    payload = b"ctr-bytes" * 100
    blob = xqsdk.encrypt_file(payload, key=b"k", algorithm="CTR")
    assert isinstance(blob, (bytes, bytearray))
    pt = xqsdk.decrypt_file(blob, key=b".2k", algorithm=None)
    assert pt == payload

def test_decrypt_file_outfile_handle_non_ctr(xqsdk, tmp_path):
    payload = b"abcXYZ"
    blob = xqsdk.encrypt_file(payload, key=b"k", algorithm="GCM")
    out_handle_path = tmp_path / "pt.bin"
    with open(out_handle_path, "wb") as fh:
        ret = xqsdk.decrypt_file(blob, key=b".1k", algorithm=None, out_file=fh)
        assert ret is None
    assert out_handle_path.read_bytes() == payload

def test_decrypt_file_from_bytes_source(xqsdk):
    payload = b"bytes-src"
    blob = xqsdk.encrypt_file(payload, key=b"k", algorithm="OTP") 
    pt = xqsdk.decrypt_file(blob, key=b".Bk", algorithm=None)      
    assert pt == payload

def test_decrypt_file_raises_when_no_prefix_and_no_algorithm(xqsdk):
    payload = b"no-prefix"
    blob = xqsdk.encrypt_file(payload, key=b"k", algorithm="GCM")
    with pytest.raises(XQException, match="Unable to determine algorithm"):
        xqsdk.decrypt_file(blob, key=b"k", algorithm=None)

def test_encrypt_file_ctr_streams_to_handle_and_decrypt(xqsdk, tmp_path):
    payload = b"file-streaming-payload" * 1000

    enc_path = tmp_path / "enc.bin"
    out_path = xqsdk.encrypt_file(payload, key=b"k", algorithm="CTR", out_file=enc_path)
    assert os.path.exists(out_path)

    dec_path = tmp_path / "dec.bin"
    out = xqsdk.decrypt_file(enc_path, key=b".2k", algorithm=None, out_file=dec_path)
    assert out == str(dec_path)
    assert dec_path.read_bytes() == payload

def test_decrypt_infers_prefixes(xqsdk):
    payload = b"abc123"

    # OTP (.B)
    blob = xqsdk.encrypt_file(payload, key=b"k", algorithm="OTP")
    pt = xqsdk.decrypt_file(blob, key=b".Bk", algorithm=None)
    assert pt == payload

    # GCM (.1)
    blob = xqsdk.encrypt_file(payload, key=b"k", algorithm="GCM")
    pt = xqsdk.decrypt_file(blob, key=b".1k", algorithm=None)
    assert pt == payload

    # CTR (.2)
    blob = xqsdk.encrypt_file(payload, key=b"k", algorithm="CTR")
    pt = xqsdk.decrypt_file(blob, key=b".2k", algorithm=None)
    assert pt == payload
