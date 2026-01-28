#######################################################
# WARNING: these are full integration tests
#   and will hit the live api to ensure compatability
#
#   THESE TESTS WILL PASS IF NOT SET
########################################################
import pytest
import warnings
from xq import XQ



def credentials_not_set():
    try:
        XQ()
        return False  # credentials looks good
    except:
        warnings.warn(
            "XQ API credentials were not found, unable to run integration tests!"
        )
        return True  # unable to init with credentials


@pytest.mark.skipif(credentials_not_set(), reason="XQ API credentials not set")
def test_roundtrip_create_and_add_packet():
    # init SDK (creds from ENV or input params)
    xq = XQ()

    # get user authentication token
    email = "mockuser1@xqtest.com"
    xq.api.login_alias(email)

    # create key packet from quantum entropy
    KEY = xq.generate_key_from_entropy()
    locator_token = xq.api.create_and_store_packet(recipients=[email], key=KEY)


    # encrypt something
    message_to_encrypt = "sometexttoencrypt"
    encrypted_message= xq.encrypt_message(
        message_to_encrypt, key=KEY, algorithm="AES"
    )

    # get key packet by lookup
    retrieved_key_packet = xq.api.get_packet(locator_token)

    # deycrypt
    decrypted_message = xq.decrypt_message(
        encrypted_message, key=retrieved_key_packet, algorithm="AES"
    )

    assert decrypted_message == message_to_encrypt


@pytest.mark.skipif(credentials_not_set(), reason="XQ API credentials not set")
def test_roundtrip_create_and_add_packets():
    # init SDK (creds from ENV or input params)
    xq = XQ()

    # get user authentication token
    email = "mockuser@xqtest.com"
    xq.api.authorize_alias(email)

    # create key packet from qunatum entropy
    KEY1 = xq.generate_key_from_entropy()

    KEY2 = xq.generate_key_from_entropy()

    locator_tokens_by_key = xq.api.create_and_store_packets(recipients=[email], keys=[KEY1, KEY2])

    keys_by_locator_token = {}
    for entry in zip(locator_tokens_by_key):
        for key, value in entry[0].items():
            keys_by_locator_token[value] = key

    locator_tokens = []
    for entry in locator_tokens_by_key:
        for locator in entry.values():
            locator_tokens.append(locator)


    # get key packet by lookup
    retrieved_keys_by_locator_tokens  = xq.api.get_packets(locator_tokens)


    assert retrieved_keys_by_locator_tokens == keys_by_locator_token

if __name__ == "__main__":
    test_roundtrip_create_and_add_packet()
    test_roundtrip_create_and_add_packets


#the following actions in the followling 2 methods  is now run interactively in examples/packet.py
#@pytest.mark.skipif(credentials_not_set(), reason="XQ API credentails not set")
#def test_revoke_key():
#   # init SDK (creds from ENV or input params)
#    xq = XQ()

#    # get user authentication token
#    email = "testmock@xqtest.com"
#    xq.api.authorize_alias(email)

    # create key packet from qunatum entropy
#    KEY = xq.generate_key_from_entropy()
#    locator_token = xq.api.create_and_store_packet(recipients=[email], key=KEY)

#    # get key packet - should be successful
#    retrieved_key_packet = xq.api.get_packet(locator_token)
#    assert retrieved_key_packet

    # revoke key
#    retrieved_key_packet = xq.api.revoke_packet(locator_token)

    # get key packet - should be gone
#    with pytest.raises(XQException):
#        retrieved_key_packet = xq.api.get_packet(locator_token)


#@pytest.mark.skipif(credentials_not_set(), reason="XQ API credentails not set")
#def test_revoke_users():
    # init SDK (creds from ENV or input params)
#    xq = XQ()

    # get user authentication token
#    email = "testmock@xqtest.com"
#    xq.api.login_alias(email)

    # create key packet from qunatum entropy
#    KEY = xq.generate_key_from_entropy()
#    locator_token = xq.api.create_and_store_packet(recipients=[email], key=KEY)

#    # grant user access
#    email1 = "goodguy@xqtest.com"
#    email2 = "badguy@xqtest.com"
#    xq.api.grant_users(locator_token, [email1, email2], alias_access=True)

    # revoke badguy
#    xq.api.revoke_users(locator_token, [email2], alias_access=True)

    # veryfiy goodguy
#    xq.api.login_alias(email1)
#    retrieved_key_packet = xq.api.get_packet(locator_token)
#    assert retrieved_key_packet

    # verify badguy
#    xq.api.login_alias(email2)
#    with pytest.raises(XQException):
#        retrieved_key_packet = xq.api.get_packet(locator_token)

if __name__ == "__main__":
    pass
    test_roundtrip_create_and_add_packet()
    test_roundtrip_create_and_add_packets()






# @pytest.mark.skipif(credentials_not_set(), reason="XQ API credentails not set")
# def test_dashboard_auth():
#     # NOTE: OBE, see test_usergroups. requires signup for auth
#     xq = XQ()
#     assert xq.api.dashboard_login()


# NOTE: this cannot be tested automatically due to the magic-link requirement
# @pytest.mark.skipif(credentials_not_set(), reason="XQ API credentails not set")
# def test_usergroups():
#     xq = XQ()

#     email = "mocker@xqtest.com"
#     password = "supersecret"

#     assert xq.api.dashboard_signup(email=email, password=password)
#     assert xq.api.dashboard_login(email=email, password=password)

#     # test adding a business contact
#     xq.api.add_contact("Mock", "Mocker", "mocker@xqtest.com", "Chief Mocker Officer", 6)

#     # add a usergroup
#     res = xq.api.create_usergroup()
#     print("CREATED GROUP")
#     print(res)

#     # request created usergroup
#     ug = xq.api.get_usergroup()
#     print("GOT USERGROUP")
#     print(ug)
