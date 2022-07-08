import pytest
import os
from io import StringIO, BytesIO
import random
import string

conftest_dir = os.path.dirname(__file__)


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
def docxFilePath():
    return f"{conftest_dir}/samples/word-example.docx"


@pytest.fixture()
def pdfFilePath():
    return f"{conftest_dir}/samples/pdf-example.pdf"


@pytest.fixture()
def largePlaintextFilelike():
    return StringIO(
        "".join(random.choice(string.ascii_lowercase) for i in range(99999))
    )


@pytest.fixture()
def largeBinaryFilelike():
    longString = "".join(random.choice(string.ascii_lowercase) for i in range(99999))
    return BytesIO(longString.encode())
