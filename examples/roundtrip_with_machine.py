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
device = input(f"Please provide the device name that will be used for authentication:")
businessId = input(f"Please provide the business ID that will be used for authentication:")
recipients = input(f"Please provide the recipients that will be used for authentication (If you wish to do multiple split using a comma):")
xq.api.authorize_device(device=device, business_id=businessId)

# create key packet
MYSUPERSECRETKEY = xq.generate_key_from_entropy()

# encrypt something
message_to_encrypt = "sometexttoencrypt"
print("\nencrypting message:", message_to_encrypt)
encrypted_message = xq.encrypt_message(
    message_to_encrypt, key=MYSUPERSECRETKEY, algorithm="CTR"
)
print("\nencrypted_message", encrypted_message)

# Create and store the encrypted key packet
locator_token = xq.api.create_and_store_packet(recipients=[recipients.split(',')], key=MYSUPERSECRETKEY, type="msg", subject='TraianTestingProd')

# get key packet by lookup
retrieved_key_packet = xq.api.get_packet(locator_token)

# deycrypt
decrypted_message = xq.decrypt_message(
    encrypted_message, key=retrieved_key_packet, algorithm="CTR"
)
print("\ndecrypted message:", decrypted_message)
