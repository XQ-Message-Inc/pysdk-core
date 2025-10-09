import io
import os
import tempfile
import pytest
from xq.algorithms.aes_encryption import AESEncryption

# ---- Fixtures ---------------------------------------------------------------

@pytest.fixture
def key_bytes():
    return b"default_secret_key"

@pytest.fixture
def aes_gcm(key_bytes):
    return AESEncryption(key_bytes, scheme=1)

@pytest.fixture
def aes_ctr(key_bytes):
    return AESEncryption(key_bytes, scheme=2)

# ---- Tests ------------------------------------------------------------------

def test_encrypt_decrypt_gcm_inmemory_default_key(aes_gcm):
    pt = "hello gcm"
    ct = aes_gcm.encrypt(pt)            
    out = aes_gcm.decrypt(ct)         
    assert out == pt

def test_encrypt_decrypt_gcm_inmemory_with_password(aes_gcm):
    pt = "hello gcm with pw"
    pw = "pw123"
    ct = aes_gcm.encrypt(pt, password=pw)
    out = aes_gcm.decrypt(ct, password=pw)
    assert out == pt

def test_encrypt_decrypt_gcm_streaming_bytesio(aes_gcm):
    pt = b"streaming gcm data"
    src = io.BytesIO(pt)
    ct = aes_gcm.encrypt(src.getvalue())
    out = aes_gcm.decrypt(io.BytesIO(ct))
    assert out.encode() == pt

def test_encrypt_decrypt_ctr_inmemory(aes_ctr):
    pt = "ctr mode roundtrip"
    ct = aes_ctr.encrypt(pt)                 
    out = aes_ctr.decrypt(ct)                
    assert out == pt

def test_encrypt_decrypt_ctr_streaming(tmp_path, aes_ctr):
    pt = ("0123456789ABCDEF" * 100_000).encode() 
    src = io.BytesIO(pt)

    enc_path = tmp_path / "enc.bin"
    with open(enc_path, "wb") as f:
        ret = aes_ctr.encrypt(src, out_file=f)    
        assert ret is None

    dec_path = tmp_path / "dec.txt"
    with open(enc_path, "rb") as f_in, open(dec_path, "wb") as f_out:
        ret = aes_ctr.decrypt(f_in, out_file=f_out)
        assert ret is None

    with open(dec_path, "rb") as f:
        assert f.read() == pt

def test_large_chunked_ctr_inmemory(aes_ctr):
    big = ("XQ" * (1024 * 1024 + 5000)) 
    ct = aes_ctr.encrypt(big)
    out = aes_ctr.decrypt(ct)
    assert out == big

def test_add_header_salt_appends_existing(aes_gcm):
    original = bytearray(b"HEAD")
    ctx = aes_gcm.add_header_salt(header=original)
    hdr = ctx["header"]
    assert hdr.startswith(b"HEAD")
    assert b"Salted__" in hdr[len(b"HEAD"):]

def test_decrypt_invalid_magic_inmemory_raises(aes_gcm):
    with pytest.raises(ValueError, match="Salted__"):
        aes_gcm.decrypt(b"not_a_valid_header")

def test_decrypt_invalid_magic_stream_raises(aes_gcm):
    with pytest.raises(ValueError, match="Salted__"):
        aes_gcm.decrypt(io.BytesIO(b"nope"))

def test_gcm_wrong_password_raises(aes_gcm):
    pt = "secret text"
    ct = aes_gcm.encrypt(pt, password="rightpw")
    with pytest.raises(ValueError):      
        aes_gcm.decrypt(ct, password="wrongpw")

def test_gcm_truncated_tag_raises(aes_gcm):
    pt = "with tag"
    ct = bytearray(aes_gcm.encrypt(pt))
    del ct[-5:]
    with pytest.raises(ValueError):
        aes_gcm.decrypt(bytes(ct))

def test_encrypt_bytes_input_gcm(aes_gcm):
    pt = b"bytes input ok"
    ct = aes_gcm.encrypt(pt)
    out = aes_gcm.decrypt(ct)
    assert out.encode() == pt

def test_empty_plaintext_gcm(aes_gcm):
    ct = aes_gcm.encrypt("")
    out = aes_gcm.decrypt(ct)
    assert out == ""

def test_pbkdf2_params_length_and_iterations(aes_gcm):
    salt = os.urandom(16)
    k32 = aes_gcm.derive_key(salt, b"pw", iterations=512, key_length=32)
    k16 = aes_gcm.derive_key(salt, b"pw", iterations=512, key_length=16)
    assert len(k32) == 32 and len(k16) == 16
    assert k32 != k16

def test_ctr_uses_iv_size_16(aes_ctr):
    pt = "check iv size behavior"
    ct = aes_ctr.encrypt(pt)
    assert ct[:8] == b"Salted__"
    assert len(ct) > 8 + 16 + 16 