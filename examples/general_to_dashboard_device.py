###############################################################################
#
# Example Dashboard interaction
#
# Assumptions:
#     XQ_API_KEY and XQ_DASHBOARD_API_KEY are defined in the ENV or .env file
#
# Prerequisits found @
#   https://github.com/XQ-Message-Inc/python-sdk
#
###############################################################################
from xq import XQ

xq = XQ()

# get user authentication token
email = input(f"Please provide the email address that will be used for authentication:")

xq.api.authorize_user(email)

# 2FA
pin = input(f"Please provide the PIN sent to the email address '{email}':")
xq.api.code_validate(pin)

# exchange for token
new_key = xq.api.exchange_key()

# exchange for dashboard token
xq.api.exchange_for_dashboard_token()

# Generate a device certificate
device_cert = xq.api.generate_device_certificate(tag="pythonSDKExample")

# Authorize device using certificate you can set output paths or use the returned dict values but you should re-use certificates
xq.api.authorize_device_cert(cert_id=device_cert["id"], cert_file_path=device_cert["clientCert"], transport_key_file_path=device_cert["transportKey"], private_key_file_path=device_cert["clientKey"], device_name="example_device")

# exchange for dashboard token for the device
xq.api.exchange_for_dashboard_token()

# add a usergroup
new_usergroup = xq.api.create_usergroup(
    name="test1", members=["oldmember@xq.com"]
)
print("CREATED GROUP:")
print(new_usergroup)

# request all usergroups
all_groups = xq.api.get_usergroup()
print("\n\nGOT ALL USERGROUPS:")
print(all_groups)

# request created usergroup by id
requested_usergroup = xq.api.get_usergroup(usergroup_id=new_usergroup["id"])
print("\n\nGOT USERGROUP BY ID:")
print(requested_usergroup)

# encrypt a value with entire usergroup as recipient
encrypted_value = xq.encrypt_auto("This is a secret message for the usergroup", algorithm="GCM", recipients=[f"{new_usergroup['id']}@_"], type=3)
print("Encrypted value for usergroup:", encrypted_value)

# decrypt a value with a user from the usergroup
decrypted_value = xq.decrypt_auto(encrypted_value)
print("Decrypted value for usergroup:", decrypted_value)

# delete usergroup
print("\n\nDELETING USERGROUP BY ID:", new_usergroup["id"])
res = xq.api.delete_usergroup(usergroup_id=new_usergroup["id"])
print("deleted:", res)

# verify delete
try:
    res = xq.api.get_usergroup(usergroup_id=new_usergroup["id"])
    print("BAD! Found deleted:", res)
except:
    print("Does not exist! We are good")
