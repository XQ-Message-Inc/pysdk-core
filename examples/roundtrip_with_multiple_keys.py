###############################################################################
#
# Example of encrypting multiple messages with multiple keys
#
# Assumptions:
#     XQ_API_KEY and XQ_DASHBOARD_API_KEY are defined in the ENV or .env file
#
# Prerequisits found @
#   https://github.com/XQ-Message-Inc/python-sdk
#
###############################################################################
import base64
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

# Messages to encrypt
messages_to_encrypt = ["sometexttoencrypt","someothertexttoencrypt"]
keys = []
encrypted_messages = []

for message_to_encrypt in messages_to_encrypt:
    # create key packet from qunatum entropy
    KEY = xq.generate_key_from_entropy()

    # encrypt something
    print("\nencrypting message:", message_to_encrypt)
    encrypted_message, nonce, tag = xq.encrypt_message(
        text=message_to_encrypt, key=KEY, algorithm="AES"
    )

    combined_message = base64.b64encode(nonce).decode() + base64.b64encode(encrypted_message).decode()

    # Store the encrypted message
    encrypted_messages.append(combined_message)

    # Store the key used for encryption
    keys.append(KEY)

# Create and store the encrypted key packets
result = xq.api.create_and_store_packets(keys=keys, recipients=[email])
locator_tokens = [list(d.values())[0] for d in result['tokens']]

# Pre-append the locatortokens to the encrypted messages
encrypted_messages = [locator_tokens[i] + encrypted_messages[i] for i in range(len(encrypted_messages))]

# Get key packets utilizing the locator tokens
keys = xq.api.get_packets(locator_tokens)

for encrypted_message in encrypted_messages:
    # decrypt
    decrypted_message = xq.decrypt_message(
        base64.b64decode(encrypted_message[67:]), key=keys[encrypted_message[:43]], algorithm="AES", nonce=base64.b64decode(encrypted_message[43:67])
    )
    print("\ndecrypted message:", decrypted_message)
