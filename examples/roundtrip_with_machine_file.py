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

# Initialize the SDK using environment variables or input parameters
xq = XQ()

# Authenticate the device
device = input(f"Please provide the device name that will be used for authentication:")
businessId = input(f"Please provide the business ID that will be used for authentication:")
recipients = input(f"Please provide the recipients that will be used for authentication (If you wish to do multiple split using a comma):")
xq.api.authorize_device(device=device, business_id=businessId)

# Generate a key packet and store it
MYSUPERSECRETKEY = xq.generate_key_from_entropy()

# make a file
tmp_file_path = os.path.dirname(os.path.abspath(__file__)) + "/fileToEncrypt.txt"
with open(tmp_file_path, "w") as fh_write:
    fh_write.write("A test file that will get encrypted with XQ")

# encrypt file
with open(tmp_file_path, "r+b") as file:
    encryptedText = xq.encrypt_file(file, MYSUPERSECRETKEY, algorithm="GCM", recipients=[recipients.split(',')])
    file.seek(0)
    file.write(encryptedText)
    file.truncate()

# Rename the file to add the .xqf extension
new_file_path = tmp_file_path + ".xqf"
os.rename(tmp_file_path, new_file_path)

with open(new_file_path, "rb") as file:
    decrypted_file = xq.decrypt_file(file, algorithm="GCM")
    print("\nDecrypted File Contents:", decrypted_file.decode())
