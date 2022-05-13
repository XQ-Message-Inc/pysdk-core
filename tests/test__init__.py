import pytest
from unittest.mock import MagicMock, patch
import os

from xq import *
from xq.api import XQAPI
from xq.exceptions import SDKConfigurationException
from xq import config


@pytest.fixture
def key_verify_failure():
    return (401, "{'status': 'Failed to locate API key'}")


@pytest.fixture
def key_verify_success():
    return (
        200,
        "{'scopes': ['authorize', 'combine', 'exchange', 'packet', 'edit:settings', 'read:settings', 'read:subscriber', 'edit:subscriber', 'read:image', 'key', 'read:apikey', 'revoke', 'devapp', 'settings', 'delegate', 'subscriber'], 'status': 'OK'}",
    )


@patch.object(XQAPI, "api_get")
def test_xq_environ(mock_api_call, key_verify_success):
    mock_api_call.return_value = key_verify_success
    os.environ["XQ_API_KEY"] = "mockapikey"
    os.environ["XQ_DASHBOARD_API_KEY"] = "mockdashboardkey"
    assert XQ(api_key="mockapikey", dashboard_api_key="mockdashboardkey")


@patch.object(XQAPI, "api_get")
def test_xq_input(mock_api_call, key_verify_success):
    mock_api_call.return_value = key_verify_success
    assert XQ(api_key="mockapikey", dashboard_api_key="mockdashboardkey")


@patch.object(XQAPI, "api_get")
def test_valid_api_key(mock_api_call, key_verify_success):
    mock_api_call.return_value = key_verify_success
    XQ(api_key="mockapikey", dashboard_api_key="mockdashboardkey")


@patch.object(XQAPI, "api_get")
def test_invalid_api_key(mock_api_call, key_verify_failure):
    mock_api_call.return_value = key_verify_failure
    with pytest.raises(SDKConfigurationException):
        XQ(api_key="mockapikey", dashboard_api_key="mockdashboardkey")


@patch.object(XQAPI, "api_get")
def test_missing_api_key(mock_api_call, key_verify_success):
    mock_api_call.return_value = key_verify_success
    with pytest.raises(SDKConfigurationException):
        XQ()


def test_encrypt_message(mock_xq):
    assert mock_xq.encrypt_message(
        text="sometexttoencrypt",
        key=b"thisisabytestext",
        algorithm="AES",
    )


def test_encrypt_message_stingkey(mock_xq):
    assert mock_xq.encrypt_message(
        text="sometexttoencrypt", key="thisisabytestext", algorithm="AES"
    )


def test_generate_key_from_entropy(mock_xq):
    entropy128 = "MmJjMjc4MzU1N2RkYjdkODYzY2YzNmZmOGRhMDMxZmM="
    mock_xq.api.get_entropy = MagicMock(return_value=entropy128)
    key = mock_xq.generate_key_from_entropy()

    assert len(key) == len(base64.b64decode(entropy128))
    assert len(key) in [16, 24, 32]


# def test_decrypt_message(mock_xq):
#     mock_xq.decrypt_message(
#         "mockencryption",
#         key=b"thisisabytestext",
#         algorithm="AES",
#         nonce=None
#     )

# def test_decrypt_message_stringkey(mock_xq):
#     mock_xq.decrypt_message(
#         "mockencryption",
#         key="thisisabytestext",
#         algorithm="AES",
#         nonce=None
#     )


def test_file_encryption(mock_xq, tmp_path):
    text = "text to encrypt"
    fh = tmp_path / "filetoencrypt"
    fh.write_text(text)

    encryptedText, expanded_key = mock_xq.encrypt_file(fh, key="thisisabytestext")
    decrypted_file = mock_xq.decrypt_file(encryptedText, key=expanded_key)

    assert decrypted_file.getvalue() == text


def test_magic_encryption_text(mock_xq):
    entropy128 = "MmJjMjc4MzU1N2RkYjdkODYzY2YzNmZmOGRhMDMxZmM="
    mock_xq.api.get_entropy = MagicMock(return_value=entropy128)

    long_key = mock_xq.generate_key_from_entropy()
    mock_xq.generate_key_from_entropy = MagicMock(
        return_value=long_key
    )  # stochastic, we have to override

    mock_xq.api.create_packet = MagicMock(return_value="mockencryptionpacket")
    mock_xq.api.add_packet = MagicMock(return_value="mocktoken123")
    mock_xq.api.get_packet = MagicMock(return_value=long_key)

    # encrypt
    message = "something to encrypt"
    magic_bundle = mock_xq.magic_encrypt(message, recipients=["mock@xqtest.com"])

    # decrypt
    plaintext = mock_xq.magic_decrypt(magic_bundle)

    assert plaintext == message


def test_magic_encryption_file(mock_xq, tmp_path):
    entropy128 = "MmJjMjc4MzU1N2RkYjdkODYzY2YzNmZmOGRhMDMxZmM="
    mock_xq.api.get_entropy = MagicMock(return_value=entropy128)
    long_key = mock_xq.generate_key_from_entropy()
    mock_xq.generate_key_from_entropy = MagicMock(
        return_value=long_key
    )  # stochastic, we have to override
    mock_xq.api.create_packet = MagicMock(return_value="mockencryptionpacket")
    mock_xq.api.add_packet = MagicMock(return_value="mocktoken123")
    mock_xq.api.get_packet = MagicMock(return_value=long_key)

    # make a file
    # tmp_file_path = "/tmp/filetoencrypt"
    filecontent = "some text to encrypt"
    fh = tmp_path / "filetoencrypt"
    fh.write_text(filecontent)

    # encrypt
    magic_bundle = mock_xq.magic_encrypt(fh, recipients=["mock@xqtest.com"])

    # decrypt
    decrypted_file = mock_xq.magic_decrypt(magic_bundle)

    assert decrypted_file.getvalue() == filecontent
