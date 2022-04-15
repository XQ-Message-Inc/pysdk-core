#######################################################
# WARNING: these are full integration tests
#   and will hit the live api to ensure compatability
#
# PREREQS: XQ_API_KEY, XQ_DASHBOARD_API_KEY must
#   be set in the ENV or .env file
#
#   THESE TESTS WILL PASS IF NOT SET
########################################################
import pytest
import warnings
from xq import XQ
from xq.exceptions import XQException


def credentials_not_set():
    try:
        XQ()
        return False  # credentials looks good
    except:
        warnings.warn(
            "XQ API credentials were not found, unable to run integration tests!"
        )
        return True  # unable to init with credentials


@pytest.mark.skipif(credentials_not_set(), reason="XQ API credentails not set")
def test_roundtrip():
    # init SDK (creds from ENV or input params)
    xq = XQ()

    # get user authentication token
    email = "mockuser@xqtest.com"
    xq.api.authorize_alias(email, "test", "runner")

    # create key packet from qunatum entropy
    KEY = xq.generate_key_from_entropy()
    encrypted_key_packet = xq.api.create_packet(recipients=[email], key=KEY)

    # store key packet
    locator_token = xq.api.add_packet(encrypted_key_packet)

    # encrypt something
    message_to_encrypt = "sometexttoencrypt"
    encrypted_message, nonce, tag = xq.encrypt_message(
        message_to_encrypt,
        key=KEY,
        algorithm="AES",
        recipients=[email],
    )

    # get key packet by lookup
    retrieved_key_packet = xq.api.get_packet(locator_token)

    # deycrypt
    decrypted_message = xq.decrypt_message(
        encrypted_message, key=retrieved_key_packet, algorithm="AES", nonce=nonce
    )

    assert decrypted_message == message_to_encrypt


@pytest.mark.skipif(credentials_not_set(), reason="XQ API credentails not set")
def test_revoke_key():
    # init SDK (creds from ENV or input params)
    xq = XQ()

    # get user authentication token
    email = "testmock@xqtest.com"
    xq.api.authorize_alias(email, "test", "runner")

    # create key packet from qunatum entropy
    KEY = xq.generate_key_from_entropy()
    encrypted_key_packet = xq.api.create_packet(recipients=[email], key=KEY)

    # store key packet
    locator_token = xq.api.add_packet(encrypted_key_packet)

    # get key packet - should be successful
    retrieved_key_packet = xq.api.get_packet(locator_token)
    assert retrieved_key_packet

    # revoke key
    retrieved_key_packet = xq.api.revoke_packet(locator_token)

    # get key packet - should be gone
    with pytest.raises(XQException):
        retrieved_key_packet = xq.api.get_packet(locator_token)
