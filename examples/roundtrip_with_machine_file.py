###############################################################################
#
# Example file encryption lifecycle, using an XQ generated qunatum key
#
# Assumptions:
#     XQ_API_KEY is defined in the ENV or .env file
#
# Prerequisits found @
#   https://github.com/XQ-Message-Inc/python-sdk
#
###############################################################################
from xq import XQ
import os 

# Initialize the SDK using environment variables or input parameters
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

# Generate a key packet and store it
MYSUPERSECRETKEY = xq.generate_key_from_entropy()

# make a file
tmp_file_path = os.path.dirname(os.path.abspath(__file__)) + "/fileToEncrypt.txt"
with open(tmp_file_path, "w") as fh_write:
    fh_write.write("A test file that will get encrypted with XQ")

# encrypt file
with open(tmp_file_path, "r+b") as file:
    encryptedText = xq.encrypt_file(file, MYSUPERSECRETKEY, algorithm="GCM", recipients=[email])
    file.seek(0)
    file.write(encryptedText)
    file.truncate()

# Rename the file to add the .xqf extension
new_file_path = tmp_file_path + ".xqf"
os.rename(tmp_file_path, new_file_path)

with open(new_file_path, "rb") as file:
    decrypted_file = xq.decrypt_file(file, algorithm="GCM")
    print("\nDecrypted File Contents:", decrypted_file.decode())

#switch back to token used to create the certificate
xq.api.headers.update({"authorization": f"Bearer {access_token}"})

# Delete the certificate
xq.api.delete_certificate(cert_id)
