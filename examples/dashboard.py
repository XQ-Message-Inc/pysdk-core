###############################################################################
#
# Example Dashboard interaction
#
# Assumptions:
#     XQ_API_KEY is defined in the ENV or .env file
#
# Prerequisits found @
#   https://github.com/XQ-Message-Inc/python-sdk
#
###############################################################################
from xq import XQ

xq = XQ()

email = input(f"Please provide the email address that will be used for authentication:")

# NOTE: password authentication to dashboard is not currently suppored by the API

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

xq.api.switch(teamId)

assert xq.api.validate_access_token()  # verify access token

#Add team member
res = xq.api.add_team_member("Mock", "Mocker", "test@xqtest.com", "Chief Mocker Officer", "User")
id = res["id"]
print(f"id {id} returned from add_contact")

#Delete team member
xq.api.delete_team_member(id)


# add a usergroup
new_usergroup = xq.api.create_usergroup(
    name="testusergroup", members=[email]
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
    name="renamed usergroup"
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
