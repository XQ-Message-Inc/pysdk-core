from xq.algorithms.encryption import *


def test_encryption():
    enc = Encryption(b"yesthisissixteen")
    assert enc
