###############################################################################
#
# Example for when you just want something encrypted, and you don't know what,
#   or care how, just that it is XQ secure
#
# Assumptions:
#     XQ_API_KEY and XQ_DASHBOARD_API_KEY are defined in the ENV or .env file
#
# Prerequisits found @
#   https://github.com/XQ-Message-Inc/python-sdk
#
###############################################################################
from pydoc import plain
from xq import XQ

# init SDK (creds from ENV or input params)
xq = XQ()

# authenticate
email = input(f"Please provide the email address that will be used for authentication:")
first_name = input(f"Please provide your first name:")
last_name = input(f"Please provide your last name:")
xq.api.authorize_alias(email, first_name, last_name)

# make a file
tmp_file_path = "/tmp/filetoencrypt"
filecontent = "some text to encrypt"
with open(tmp_file_path, "w") as fh_write:
    fh_write.write(filecontent)

# encrypt
magic_bundle = xq.magic_encrypt(tmp_file_path, recipients=[email])

# decrypt
decrypted_file = xq.magic_decrypt(magic_bundle)

assert decrypted_file.getvalue() == filecontent
