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
password = "nonsense"

# NOTE: password authentication to dashboard is not currently suppored by the API
xq.api.dashboard_signup(email=email)
xq.api.send_login_link(email=email)
password = input(f"Paste magic link sent to {email}:")
xq.api.dashboard_login(email=email, password=password)
res = xq.api.login_verify()
assert xq.api.validate_access_token()

# adding a business contact
# xq.api.add_contact("Mock", "Mocker", "mocker@xqtest.com", "Chief Mocker Officer", 6)

# add a usergroup
res = xq.api.create_usergroup(
    usergroup_id=1, members=["mock@xqtest.com"], name="testusergroup"
)
print("CREATED GROUP")
print(res)

# request created usergroup
ug = xq.api.get_usergroup(usergroup_id=1)
print("GOT USERGROUP")
print(ug)
