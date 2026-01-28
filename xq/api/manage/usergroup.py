##
# WARNING: THIS IS ALL MADE UP, THERE ARE NO DOCS
#
# Assumed Requirements: Full CRUD on https://dashboard.xqmsg.net/v2/usergroup
##
from typing import List

from xq.exceptions import XQException
from xq.api.manage import API_SUBDOMAIN


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

    status_code, res = api.api_post("group", json=params, subdomain=API_SUBDOMAIN)

    if status_code == 200:
        return res
    else:
        raise XQException(message=f"Error creating Dashboard usergroup: {res}")


def get_usergroup(api, usergroup_id: int = None):
    """get a usergroup by id
    https://xqmsg.com/docs/delta/#tag/user-group-management/get/v3/group/{id}

    :param api: XQAPI instance
    :type api: XQAPI
    :param usergroup_id: id of usergroup, defaults to None
    :type usergroup_id: int, optional
    :param groups: _description_ TODO, defaults to None
    :type groups: List[str], optional
    :raises XQException: error getting usergroup
    :return: usergroup(s)
    :rtype: dict
    """

    if usergroup_id:
        endpoint = f"group/{usergroup_id}"
    else:
        endpoint = "groups"

    status_code, res = api.api_get(endpoint, subdomain=API_SUBDOMAIN)

    if status_code == 200:
        return res
    else:
        raise XQException(message=f"Error getting Dashboard usergroup: {res}")


def update_usergroup(api, usergroup_id: int, name: str = None, members: List[str] = []):
    """update a usergroup by id
    https://xqmsg.com/docs/delta/#tag/user-group-management/patch/v3/group/{id}

    :param api: XQAPI instance
    :type api: XQAPI
    :param usergroup_id: id of usergroup
    :type usergroup_id: int
    :param name: new name of usergroup
    :type name: str
    :param members: new usergroup members
    :type members: List[str]
    :raises XQException: error updating usergroup
    :return: updated usergroup
    :rtype: object
    """
    params = {}
    if members:
        params["addMembers"] = members
    if name:
        params["name"] = name

    status_code, res = api.api_patch(
        f"group/{usergroup_id}", json=params, subdomain=API_SUBDOMAIN
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
        f"group/{usergroup_id}", subdomain=API_SUBDOMAIN
    )

    if status_code == 204:
        return True
    else:
        raise XQException(message=f"Error deleting group: {res}")
