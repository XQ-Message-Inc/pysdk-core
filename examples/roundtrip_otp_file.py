###############################################################################
#
# Example file encryption lifecycle, using an XQ generated qunatum key
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
xq.api.authorize_alias(email, first_name, last_name)

# create key packet from qunatum entropy
KEY = xq.generate_key_from_entropy()

# make a file
tmp_file_path = "/tmp/filetoencrypt"
with open(tmp_file_path, "w") as fh_write:
    fh_write.write("some text to encrypt")

# encrypt file
encryptedText, expanded_key = xq.encrypt_file(tmp_file_path, key=KEY)
print("\nencrypted_message", encryptedText)

# Create and store the encrypted key packet
locator_token = xq.api.create_and_store_packet(recipients=[email], key=expanded_key)

# get key packet by lookup
retrieved_key_packet = xq.api.get_packet(locator_token)

# deycrypt
decrypted_file = xq.decrypt_file(encryptedText, key=retrieved_key_packet)
print("\ndecrypted message:", decrypted_file.getvalue())
