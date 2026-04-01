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
import traceback

def run(xq: XQ = None, email: str = None, access_token: str = None):
    if xq is None:
        xq = XQ()

        email = input(f"Please provide the email address that will be used for authentication:")

        xq.api.send_login_link(email=email)
        pin = input(f"Please provide the PIN sent to the email address '{email}':")

        xq.api.login_verify(pin)  #

        xq.api.exchange_key()

        #get the first team or create one
        teams = xq.api.get_teams()

        if teams:
            teamId = teams[0]["id"]
        else:
            teamId = xq.api.create_team("New team")

        xq.api.switch(teamId)

        assert xq.api.validate_access_token()  # verify access token

    #Add team member
    try:
        res = xq.api.add_team_member("Mock", "Mocker", "test@xqtest.com", "Chief Mocker Officer", "User")
        id = res["id"]
        print(f"id {id} returned from add_contact")

        team_members = xq.api.get_team_members()
        assert len(team_members["data"]) > 1

        team_member = xq.api.get_team_member(id)
        assert team_member["id"] == id

    finally:
        try:
            #Delete team member
            xq.api.delete_team_member(id)
        except:
            traceback.print_exc()

    try:
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
        requested_usergroup = xq.api.get_usergroup(usergroup_id=new_usergroup["id"], includeEmailAddress=True)
        print("\n\nGOT USERGROUP BY ID:")
        print(requested_usergroup)

        # request created usergroup by name
        requested_usergroup = xq.api.get_usergroup(name="testusergroup", includeEmailAddress=True)
        print("\n\nGOT USERGROUP BY NAME:")
        print(requested_usergroup)

        # update usergroup, adding some members and deleting a members
        print("\n\nUPDATING USERGROUP BY ID:", new_usergroup["id"])
        res = xq.api.update_usergroup(
            usergroup_id=new_usergroup["id"],
            name="renamed usergroup",
            addMembers=["xq@xqmsg.com", "xq2@xqmsg.com"],
            removeMembers=[email]
        )

        #  # verify update request updated  usergroup by id
        updated_requested_usergroup = xq.api.get_usergroup(usergroup_id=new_usergroup["id"], includeEmailAddress=True)
        print("\n\nGOT UPDATED USERGROUP BY ID:")
        print(updated_requested_usergroup)

        assert len(updated_requested_usergroup["members"]) == 2

        try:
            res = xq.api.get_usergroup(name="renamed usergroup1")
        except:
            print("Could not find group")

    finally:
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


if __name__ == "__main__":
    run()
