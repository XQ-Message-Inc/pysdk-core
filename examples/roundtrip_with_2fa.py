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
email = input(f"Please provide the email address that will be used for authentication:")
first_name = input(f"Please provide your first name:")
last_name = input(f"Please provide your last name:")
xq.api.authorize_user(email, first_name, last_name)  # returns success boolean

# 2FA
pin = input(f"Please provide the PIN sent to the email address '{email}':")
xq.api.code_validate(pin)

# exchange for token
new_key = xq.api.exchange_key()

# create key packet
MYSUPERSECRETKEY = b"itissixteenbytes"
encrypted_key_packet = xq.api.create_packet(recipients=[email], key=MYSUPERSECRETKEY)

# store key packet
locator_token = xq.api.add_packet(encrypted_key_packet)

# encrypt something
message_to_encrypt = "sometexttoencrypt"
print("\nencrypting message:", message_to_encrypt)
encrypted_message, nonce, tag = xq.encrypt_message(
    message_to_encrypt, key=MYSUPERSECRETKEY, algorithm="AES"
)
print("\nencrypted_message", encrypted_message)

# get key packet by lookup
retrieved_key_packet = xq.api.get_packet(locator_token)

# deycrypt
decrypted_message = xq.decrypt_message(
    encrypted_message, key=retrieved_key_packet, algorithm="AES", nonce=nonce
)
print("\ndecrypted message:", decrypted_message)
