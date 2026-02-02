###############################################################################
#
# Example packet apis
#
# Assumptions:
#     XQ_API_KEY is defined in the ENV or .env file
#
# Prerequisits found @
#   https://github.com/XQ-Message-Inc/python-sdk
#
###############################################################################
from xq import XQ
from xq.exceptions import XQException
import uuid

xq = XQ()

email = input(f"Please provide the email address that will be used for authentication:")

# NOTE: password authentication to dashboard is not currently suppored by the API

xq.api.send_login_link(email=email)
pin = input(f"Please provide the PIN sent to the email address '{email}':")

xq.api.login_verify(pin)  #
#assert xq.api.validate_access_token()  # verify access token

xq.api.exchange_key()

#create a team
uuid = uuid.uuid4()
uuid_string = str(uuid)
teamId = xq.api.create_team(f"{uuid_string} team", f"{uuid_string}_team")

access_token = xq.api.switch(teamId)


# get user authentication token

# create key packet from qunatum entropy
KEY = xq.generate_key_from_entropy()
locator_token = xq.api.create_and_store_packet(recipients=[email], key=KEY)

# get key packet - should be successful
retrieved_key_packet = xq.api.get_packet(locator_token)
assert retrieved_key_packet

# revoke key
retrieved_key_packet = xq.api.revoke_packet(locator_token)

# get key packet - should be gone
try:
    retrieved_key_packet = xq.api.get_packet(locator_token)
    raise XQException(message=f"Packet should have been deleted")
except:
    pass


# create key packet from quantum entropy
KEY = xq.generate_key_from_entropy()
locator_token = xq.api.create_and_store_packet(recipients=[email], key=KEY)

# grant user access
email1 = "goodguy@xqtest3.com"
email2 = "badguy@xqtest3.com"
xq.api.grant_users(locator_token, [email1, email2], alias_access=True)

# revoke badguy
xq.api.revoke_users(locator_token, [email2], alias_access=True)

# verify goodguy
xq.api.login_alias(email1)
retrieved_key_packet = xq.api.get_packet(locator_token)
assert retrieved_key_packet

# verify badguy
xq.api.login_alias(email2)
try:
    retrieved_key_packet = xq.api.get_packet(locator_token)
    # It should fail. If it reaches here throw an exception
    raise XQException(message=f"Packet should not be accessible")
except:
    pass

#switch back to token used to switch to the team
xq.api.headers.update({"authorization": f"Bearer {access_token}"})

#delete the team
xq.api.delete_team(teamId)
