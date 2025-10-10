###############################################################################
#
# Example file encryption lifecycle, using an XQ generated qunatum key
#
# Assumptions:
#     XQ_API_KEY and XQ_DASHBOARD_API_KEY are defined in the ENV or .env file
#
# Prerequisits found @
#   https://github.com/XQ-Message-Inc/python-sdk
#
###############################################################################
from xq import XQ
import os

# init SDK (creds from ENV or input params)
xq = XQ()

# get user authentication token
email = input(f"Please provide the email address that will be used for authentication:")
first_name = input(f"Please provide your first name:")
last_name = input(f"Please provide your last name:")
xq.api.authorize_user(email, first_name, last_name)  # returns success boolean

# 2FA
pin = input(f"Please provide the PIN sent to the email address '{email}':")
xq.api.code_validate(pin)

# exchange for token
xq.api.exchange_key()

# create key packet from qunatum entropy
KEY = xq.generate_key_from_entropy()

# make a file
tmp_file_path = os.path.dirname(os.path.abspath(__file__)) + "/fileToEncrypt.txt"
with open(tmp_file_path, "w") as fh_write:
    fh_write.write("A test file that will get encrypted with XQ")

# encrypt file
test = xq.encrypt_file(tmp_file_path, KEY, algorithm="OTP", recipients=[email], out_file=tmp_file_path + ".xqf")

# decrypt file
test_out = xq.decrypt_file(tmp_file_path + ".xqf", out_file=tmp_file_path)
