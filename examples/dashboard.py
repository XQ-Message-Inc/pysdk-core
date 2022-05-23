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

email = input(f"Please provide the email address that will be used for authentication:")

# NOTE: password authentication to dashboard is not currently suppored by the API
xq.api.dashboard_signup(email=email)
xq.api.send_login_link(email=email)
magic_link = input(f"Paste magic link sent to {email}:")
xq.api.dashboard_login(password=magic_link)  # set temporary access_token
res = xq.api.login_verify()  # exchange for real access_token
assert xq.api.validate_access_token()  # verify access token

# add a usergroup
new_usergroup = xq.api.create_usergroup(
    name="testusergroup", members=["oldmember@xq.com"]
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

# update usergroup
print("\n\nUPDATING USERGROUP BY ID:", new_usergroup["id"])
res = xq.api.update_usergroup(
    usergroup_id=new_usergroup["id"],
    name="renamed usergroup",
    members=["newmember@xq.com"],
)
print("updated:", res)

# verify update
res = xq.api.get_usergroup(usergroup_id=new_usergroup["id"])
print("got updated:", res)

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
