import io
import os
import builtins
from pathlib import Path
import pytest

import xq.algorithms.otp_encryption as otp_mod
from xq.algorithms.otp_encryption import OTPEncryption

# ---------- Helpers ------------------------------------------------------------------

@pytest.fixture(autouse=True)
def patch_xor_impl(monkeypatch):
    """
    Provide a pure-Python XOR fallback so tests pass even when
    xor_simd_neon_python is not available.
    """
    def xor_bytes(data: bytes, key: bytes) -> bytes:
        if isinstance(data, bytearray):
            data = bytes(data)
        if not key:
            key = b"\x00"
        out = bytearray(len(data))
        klen = len(key)
        for i, b in enumerate(data):
            out[i] = b ^ key[i % klen]
        return bytes(out)

    monkeypatch.setattr(otp_mod, "xor_simd_neon_python", xor_bytes, raising=False)

@pytest.fixture
def key_bytes():
    return b"supersecretkey"

# ---- Tests ------------------------------------------------------------------

def test_roundtrip_bytes_default_key(key_bytes):
    enc = OTPEncryption(key_bytes)
    pt = b"hello otp"
    ct = enc.encrypt(pt)
    out = enc.decrypt(ct)
    assert out == pt

def test_roundtrip_separate_instances(key_bytes):
    pt = b"separate instances ok"
    enc1 = OTPEncryption(key_bytes)
    ct = enc1.encrypt(pt)
    enc2 = OTPEncryption(key_bytes)
    out = enc2.decrypt(ct)
    assert out == pt

def test_encrypt_warns_on_str_and_decodes_to_bytes(key_bytes):
    enc = OTPEncryption(key_bytes)
    with pytest.warns(UserWarning, match="string was submitted"):
        ct = enc.encrypt("string input")
    out = enc.decrypt(ct)
    assert out == b"string input"

def test_encrypt_textio_warns(key_bytes, tmp_path):
    text_path = tmp_path / "t.txt"
    text_path.write_text("αβγ")
    with text_path.open("r", encoding="utf-8") as fh:
        enc = OTPEncryption(key_bytes)
        with pytest.warns(UserWarning, match="TextIO file"):
            ct = enc.encrypt(fh)
    assert enc.decrypt(ct) == "αβγ".encode()

def test_encrypt_stringio_warns(key_bytes):
    from io import StringIO
    sio = StringIO("stringio")
    enc = OTPEncryption(key_bytes)
    with pytest.warns(UserWarning, match="string file"):
        ct = enc.encrypt(sio)
    assert enc.decrypt(ct) == b"stringio"

def test_encrypt_bytesio(key_bytes):
    bio = io.BytesIO(b"bytesio data")
    enc = OTPEncryption(key_bytes)
    ct = enc.encrypt(bio)
    assert enc.decrypt(ct) == b"bytesio data"

def test_encrypt_posixpath(key_bytes, tmp_path):
    p = tmp_path / "bin.dat"
    p.write_bytes(b"\x00\x01\x02")
    enc = OTPEncryption(key_bytes)
    ct = enc.encrypt(p)  
    assert enc.decrypt(ct) == b"\x00\x01\x02"

def test_encrypt_buffered_reader(key_bytes, tmp_path):
    p = tmp_path / "file.bin"
    p.write_bytes(b"buffered reader")
    with p.open("rb") as fh: 
        enc = OTPEncryption(key_bytes)
        ct = enc.encrypt(fh)
    assert enc.decrypt(ct) == b"buffered reader"

def test_encrypt_unknown_type_warns_and_still_works(key_bytes):
    data = bytearray(b"bytearray data")
    enc = OTPEncryption(key_bytes)
    with pytest.warns(UserWarning, match="not officially supported"):
        ct = enc.encrypt(data)
    assert enc.decrypt(ct) == b"bytearray data"

def test_decrypt_accepts_bytearray_input(key_bytes):
    enc = OTPEncryption(key_bytes)
    pt = b"x" * 32
    ct = enc.encrypt(pt)
    out = enc.decrypt(bytearray(ct))
    assert out == pt

def test_encrypt_chunk_and_decrypt_chunk_with_offsets(key_bytes):
    enc = OTPEncryption(key_bytes)
    pw = b"pw"
    chunk = b"A" * 1003 
    enc1 = enc.encrypt_chunk(chunk, pw, key_offset=5)
    dec1 = enc.decrypt_chunk(enc1, pw, key_offset=5)
    assert dec1 == chunk

def test_large_data_multiple_chunks_via_stream_api(key_bytes, tmp_path):
    data = (b"0123456789ABCDEF" * 8192)  
    src_path = tmp_path / "src.bin"
    src_path.write_bytes(data)

    enc = OTPEncryption(key_bytes)
    header = b"HDR"  

    enc_bytes = enc.encrypt_file_streaming(
        file=os.fspath(src_path),
        password=key_bytes,
        header=header,
        out_file=None,
        chunk_size=4096,
    )
    assert enc_bytes.startswith(header)

    def fake_get_file_header(_buf, _version):
        return {"length": len(header)}
    enc.get_file_header = fake_get_file_header 

    # Now decrypt
    out = enc.decrypt_file_streaming(io.BytesIO(enc_bytes), password=key_bytes)
    assert out == data

def test_streaming_to_file_handles_key_offset_progression(key_bytes, tmp_path):
    data = (b"Z" * (1024 * 64 + 123))  
    enc = OTPEncryption(key_bytes)
    header = b"H"

    enc_path = tmp_path / "enc.bin"
    with enc_path.open("wb") as f:
        ret = enc.encrypt_file_streaming(
            file=io.BytesIO(data),
            password=key_bytes,
            header=header,
            out_file=f,
            chunk_size=8192,
        )
        assert ret is None

    enc.get_file_header = lambda _b, _v: {"length": len(header)}  
    dec = enc.decrypt_file_streaming(enc_path.open("rb"), password=key_bytes)
    assert dec == data

def test_empty_plaintext(key_bytes):
    enc = OTPEncryption(key_bytes)
    ct = enc.encrypt(b"")
    assert enc.decrypt(ct) == b""

def test_decrypt_file_streaming_with_dot_prefix_and_mock_header(monkeypatch, key_bytes):
    otp = OTPEncryption(key_bytes)

    header_core = b"XQHDR"
    header = header_core + b"\x00" * (60 - len(header_core)) 

    body = b"secret streaming payload" * 50
    enc_body = otp.encrypt(body, password=key_bytes)
    stream = io.BytesIO(header + enc_body)

    monkeypatch.setattr(
        otp, "get_file_header",
        lambda initial, version: {"length": len(header)},
        raising=False,
    )

    prefixed_pw = b".B" + key_bytes
    out = otp.decrypt_file_streaming(stream, password=prefixed_pw)
    assert out == body
