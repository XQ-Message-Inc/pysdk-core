###################################################
#
# Example message encryption lifecycle
# Prerequisits found @
#   https://github.com/XQ-Message-Inc/python-sdk
#
###################################################
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
print("\n-- creating packet --")
mysupersecret = b"itissixteenbytes"
encrypted_key_packet = xq.api.create_packet(
    recipients="adam@mediocretech.com", key=mysupersecret
)

# store key packet
print("\n-- storing packet --")
locator_token = xq.api.store_packet(encrypted_key_packet)
import urllib

print("\nlocator_token:", urllib.parse.quote_plus(locator_token))

# encrypt something
encrypted_message, tag = xq.encrypt_message(
    "sometexttoencrypt",
    key=mysupersecret,
    algorithm="AES",
    recipients=["adam@mediocretech.com"],
)
print("\nencrypted_message", encrypted_message)

# get key packet by lookup
retrieved_key_packet = xq.api.get_packet(locator_token)  # CORS issue on server?
print("\nretrieved_key_packet", retrieved_key_packet)
assert retrieved_key_packet == tag
# retrieved_key_packet = tag

# deycrypt
decrypted_message = xq.decrypt_message(
    encrypted_message, key=retrieved_key_packet, algorithm="AES"
)
print("\ndecrypted message:", decrypted_message)
