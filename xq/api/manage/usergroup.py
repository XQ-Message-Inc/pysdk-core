##
# WARNING: THIS IS ALL MADE UP, THERE ARE NO DOCS
#
# Assumed Requirements: Full CRUD on https://dashboard.xqmsg.net/v2/usergroup
##
from typing import List

from xq.exceptions import XQException


def create_usergroup(api, name: str, members: List[str]):
    """create a usergroup
    https://xqmsg.com/docs/delta/#tag/user-group-management/post/v3/group

    :param api: XQAPI instance
    :type api: XQAPI
    :param name: name of usergroup
    :type name: str
    :param members: list of member emails to add to group
    :type members: List[str]
    :raises XQException: error creating usergroup
    :return: usergroup
    :rtype: dict
    """
    params = {"members": members, "name": name}

    status_code, res = api.api_post("group", json=params)

    if status_code == 200:
        return res
    else:
        raise XQException(message=f"Error creating Dashboard usergroup: {res}")


def get_usergroup(api, usergroup_id: int = None, name: str = None, includeEmailAddress: bool = False):
    """get a usergroup by id
    https://xqmsg.com/docs/delta/#tag/user-group-management/get/v3/group/{id}

    :param api: XQAPI instance
    :type api: XQAPI
    :param usergroup_id: id of usergroup, defaults to None
    :type usergroup_id: int, optional
    :param name: name of usergroup to search for, defaults to None
    :type name: str, optional
    :param includeEmailAddress: should include email address in response, defaults to False
    :type includeEmailAddress: bool, optional
    :raises XQException: error getting usergroup
    :return: usergroup(s)
    :rtype: dict
    """

    if usergroup_id:
        endpoint, params = f"group/{usergroup_id}", {"includeEmailAddress": includeEmailAddress}
    else:
        endpoint, params = "groups", {"includeEmailAddress": includeEmailAddress, "includeMembers": True}

    status_code, res = api.api_get(endpoint, params=params)

    if status_code == 200:
        if name and not usergroup_id:
            groups = res if isinstance(res, list) else []
            matches = [g for g in groups if g.get("name") == name]
            if not matches:
                raise XQException(message=f"No usergroup found with name: {name}")
            return matches[0]
        return res
    else:
        raise XQException(message=f"Error getting Dashboard usergroup: {res}")


def update_usergroup(api, usergroup_id: int, name: str = None,
                     addMembers: List[str] = None, removeMembers: List[str] = None, addMissing: bool = None):
    """update a usergroup by id
    https://xqmsg.com/docs/delta/#tag/user-group-management/patch/v3/group/{id}

    :param api: XQAPI instance
    :type api: XQAPI
    :param usergroup_id: id of usergroup
    :type usergroup_id: int
    :param name: new name of usergroup
    :type name: str
    :param addMembers:  usergroup members to be added
    :type addMembers: List[str]
    :param removeMembers:  usergroup members to be added
    :type removeMembers: List[str]
    :param addMissing: if added members should be added to the team if not a member
    :type addMissing: bool
    :raises XQException: error updating usergroup
    :return: updated usergroup
    :rtype: object
    """
    params = {}
    if addMembers:
        params["addMembers"] = addMembers
    if name:
        params["name"] = name
    if addMissing:
        params["addMissing"] = addMissing

    if removeMembers:
        group = api.get_usergroup(usergroup_id, name, includeEmailAddress=True)
        existingMembers = group["members"]
        emailToId = {}
        removeMemberIds = []
        for item in existingMembers:
            emailToId[item["email"]] = item["id"]
        for email in removeMembers:
            id = emailToId.get(email, -1)
            if id != -1:
                removeMemberIds.append(id)
        params["removeMemberIds"] = removeMemberIds

    status_code, res = api.api_patch(
        f"group/{usergroup_id}", json=params
    )

    if status_code == 200:
        return res
    else:
        raise XQException(message=f"Error updating  usergroup: {res}")

def delete_usergroup(api, usergroup_id: int):
    """delete a usergroup by id
    https://xqmsg.com/docs/delta/#tag/user-group-management/delete/v3/group/{id}

    :param api: XQAPI instance
    :type api: XQAPI
    :param usergroup_id: id number of usergroup
    :type usergroup_id: int
    :raises XQException: error deleting usergroup
    :return: success
    :rtype: boolean
    """
    status_code, res = api.api_delete(
        f"group/{usergroup_id}"
    )

    if status_code == 204:
        return True
    else:
        raise XQException(message=f"Error deleting group: {res}")
