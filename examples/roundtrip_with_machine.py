###############################################################################
#
# Example message encryption lifecycle
#
# Assumptions:
#     XQ_API_KEY is  defined in the ENV or .env file
#
# Prerequisits found @
#   https://github.com/XQ-Message-Inc/python-sdk
#
###############################################################################
from xq import XQ

# init SDK (creds from ENV or input params)
xq = XQ()

email = input(f"Please provide the email address that will be used for authentication:")

xq.api.send_login_link(email=email)
pin = input(f"Please provide the PIN sent to the email address '{email}':")

xq.api.login_verify(pin)  #

xq.api.exchange_key()

assert xq.api.validate_access_token()  # verify access token

#get the first team or create one
teams = xq.api.get_teams()

if teams:
    teamId = teams[0]["id"]
else:
    teamId = xq.api.create_team("New team")

access_token = xq.api.switch(teamId)

res = xq.api.create_certificate("new certificate", ["127.0.0.1", "0.0.0.0"], True)
cert_id = res["id"]
cert_data = res["clientCert"]
transport_key = res["transportKey"]
private_key_content = res["clientKey"]
xq.api.login_certificate(cert_id, cert_data, transport_key, private_key_content)


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
locator_token = xq.api.create_and_store_packet(recipients=[email], key=MYSUPERSECRETKEY, type="Email", subject='TraianTestingProd')

# get key packet by lookup
retrieved_key_packet = xq.api.get_packet(locator_token)

# deycrypt
decrypted_message = xq.decrypt_message(
    encrypted_message, key=retrieved_key_packet, algorithm="CTR"
)
#print("\ndecrypted message:", decrypted_message)

#switch back to token used to create the certificate
xq.api.headers.update({"authorization": f"Bearer {access_token}"})

# Delete the certificate
xq.api.delete_certificate(cert_id)
