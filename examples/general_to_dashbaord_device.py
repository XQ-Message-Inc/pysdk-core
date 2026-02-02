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

# add a usergroup
new_usergroup = xq.api.create_usergroup(
    name="test1", members=[email]
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
encrypted_value = xq.encrypt_auto("This is a secret message for the usergroup", algorithm="GCM", recipients=[f"{new_usergroup['id']}@group.local"], type=3)
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
