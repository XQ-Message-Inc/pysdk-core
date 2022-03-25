###################################################
#
# Example message encryption lifecycle
# Prerequisits found @
#   https://github.com/XQ-Message-Inc/python-sdk
#
###################################################
from xq import XQ

# init SDK (creds from ENV or input params)
xq = XQ()

# get user authentication token
email = "adam@mediocretech.com"
auth_token = xq.authorize_user(email, "adam", "ge")  # returns success boolean

# 2FA
pin = input(f"Please provide the PIN sent to email the email address '{email}':")
xq.code_validate(pin)

# create key packet
print("\n-- creating packet --")
res = xq.create_packet(recipients="adam@mediocretech.com", auth_token=auth_token)
print("created packet")
print(res)

# store key packet
print("\n-- storing packet --")
res = xq.store_packet(res)
print("stored packet")
print(res)

# encrypt something
# xq.encrypt('sometext', )
