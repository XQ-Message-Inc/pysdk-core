###############################################################################
#
# Example Runs all the examples
#
# Assumptions:
#     XQ_API_KEY is defined in the ENV or .env file
#
# Prerequisits found @
#   https://github.com/XQ-Message-Inc/python-sdk
#
###############################################################################
from xq import XQ
from dashboard import run as runDashboard
from general_to_dashboard_device import run as runGeneralToDashBoard
from packet import run as runPacket
from roundtrip_otp_file import run as roundtripOTPFile
from roundtrip_with_2fa import run as roundtripWith2FA
from roundtrip_with_2fa_database import run as roundtripWith2FADatabase
from roundtrip_with_entropy_key import run as roundtripWithEntropy
from roundtrip_with_machine import run as roundWithMachine
from roundtrip_with_machine_file import run as roundWithMachineFile


if __name__ == "__main__":
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

    access_token = xq.api.switch(teamId)

    assert xq.api.validate_access_token()

    runDashboard(xq, email, access_token)
    print("completed runDashboard")
    runGeneralToDashBoard(xq, email, access_token)
    print("completed runGeneralToDashBoard")
    roundtripOTPFile(xq, email, access_token)
    print("completed roundtripOTPFile")
    roundtripWith2FA(xq, email, access_token)
    print("completed roundtripWith2FA")
    roundtripWith2FADatabase(xq, email, access_token)
    print("completed roundtripWith2FADatabase")
    roundtripWithEntropy(xq, email, access_token)
    print("completed roundtripWithEntropy", access_token)
    roundWithMachineFile(xq, email, access_token)
    print("completed roundWithMachineFile")
    roundWithMachine(xq, email, access_token)
    print("completed roundWithMachine")
    runPacket(xq, email, access_token)
    print("completed runPacket")
