###############################################################################
#
# Example message encryption lifecycle
#
# Assumptions:
#     XQ_API_KEY and XQ_DASHBOARD_API_KEY are defined in the ENV or .env file
#
# Prerequisits found @
#   https://github.com/XQ-Message-Inc/python-sdk
#
###############################################################################
from xq import XQ

# init SDK (creds from ENV or input params)
xq = XQ()

# get user authentication token
email = "adam@mediocretech.com"
xq.api.authorize_user(email, "adam", "ge")  # returns success boolean

# 2FA
pin = input(f"Please provide the PIN sent to the email address '{email}':")
xq.api.code_validate(pin)

# exchange for token
new_key = xq.api.exchange_key()

# create key packet
MYSUPERSECRET = b"itissixteenbytes"
encrypted_key_packet = xq.api.create_packet(
    recipients="adam@mediocretech.com", key=MYSUPERSECRET
)

# store key packet
locator_token = xq.api.add_packet(encrypted_key_packet)

# encrypt something
encrypted_message, nonce, tag = xq.encrypt_message(
    "sometexttoencrypt",
    key=MYSUPERSECRET,
    algorithm="AES",
    recipients=["adam@mediocretech.com"],
)
print("\nencrypted_message", encrypted_message)

# get key packet by lookup
# TODO:
#   this is returning `{"status":"Sorry, this message can no longer be decrypted"}`
#   despite the default expiration being set to 24
retrieved_key_packet = xq.api.get_packet(locator_token)
# retrieved_key_packet = MYSUPERSECRET
print("\nretrieved_key_packet", retrieved_key_packet)
# assert retrieved_key_packet == tag


# deycrypt - TODO: why must we encode the key packet before decrypting?
decrypted_message = xq.decrypt_message(
    encrypted_message, key=retrieved_key_packet.encode(), algorithm="AES", nonce=nonce
)
print("\ndecrypted message:", decrypted_message)
