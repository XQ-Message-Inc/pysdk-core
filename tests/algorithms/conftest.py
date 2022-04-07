import pytest
from io import StringIO, BytesIO
import random
import string


@pytest.fixture()
def key_string():
    return "yesthisissixteen"


@pytest.fixture()
def key_bytes(key_string):
    return key_string.encode()


@pytest.fixture()
def plaintextFixiture():
    return "this is a test"


@pytest.fixture()
def plaintextFilelike():
    return StringIO("some file contents")


@pytest.fixture()
def binaryFilelike():
    return BytesIO(b"some file contents")


@pytest.fixture()
def largePlaintextFilelike():
    return StringIO(
        "".join(random.choice(string.ascii_lowercase) for i in range(99999))
    )


@pytest.fixture()
def largeBinaryFilelike():
    longString = "".join(random.choice(string.ascii_lowercase) for i in range(99999))
    return BytesIO(longString.encode())
