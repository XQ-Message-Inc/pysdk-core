##
# WARNING: THIS IS ALL MADE UP, THERE ARE NO DOCS
#
# Assumed Requirements: Full CRUD on https://dashboard.xqmsg.net/v2/usergroup
##

from xq.exceptions import XQException
from xq.api.manage import API_SUBDOMAIN


def create_usergroup(api, name: str, members: list[str]):
    """create a usergroup

    :param api: XQAPI instance
    :type api: XQAPI
    :param name: name of usergroup
    :type name: str
    :param members: list of member emails to add to group
    :type members: list[str]
    :raises XQException: error creating usergroup
    :return: usergroup
    :rtype: dict
    """
    params = {"members": members, "name": name}

    status_code, res = api.api_post("usergroup", json=params, subdomain=API_SUBDOMAIN)

    if status_code == 200:
        return res
    else:
        raise XQException(message=f"Error creating Dashboard usergroup: {res}")


def get_usergroup(api, usergroup_id: int = None, groups: list[str] = None):
    """get a usergroup by id

    :param api: XQAPI instance
    :type api: XQAPI
    :param usergroup_id: id of usergroup, defaults to None
    :type usergroup_id: int, optional
    :param groups: _description_ TODO, defaults to None
    :type groups: list[str], optional
    :raises XQException: error getting usergroup
    :return: usergroup(s)
    :rtype: dict
    """
    endpoint = "usergroup"

    if usergroup_id:
        endpoint = f"{endpoint}/{usergroup_id}"
    # elif groups:
    #     # TODO: what does groups do?
    #     endpoint = f"{endpoint}/{groups}"
    else:
        pass  # return all usergroups

    status_code, res = api.api_get(endpoint, subdomain=API_SUBDOMAIN)

    if status_code == 200:
        return res
    else:
        raise XQException(message=f"Error getting Dashboard usergroup: {res}")


def update_usergroup(api, usergroup_id: int, name: str, members: list[str]):
    """update a usergroup by id
    WARNING: PATCH and PUT not supported by API

    :param api: XQAPI instance
    :type api: XQAPI
    :param usergroup_id: id of usergroup
    :type usergroup_id: int
    :param name: new name of usergroup
    :type name: str
    :param members: new usergroup members
    :type members: list[str]
    :raises XQException: error updating usergroup
    :return: updated usergroup
    :rtype: object
    """
    params = {"id": usergroup_id, "members": members, "name": name}

    status_code, res = api.api_patch("usergroup", json=params, subdomain=API_SUBDOMAIN)

    if status_code == 200:
        return res
    else:
        raise XQException(message=f"Error updating Dashbaord usergroup: {res}")


def delete_usergroup(api, usergroup_id: int):
    """delete a usergroup by id
    WARNING: DELETE not supported by API

    :param api: XQAPI instance
    :type api: XQAPI
    :param usergroup_id: id number of usergroup
    :type usergroup_id: int
    :raises XQException: error deleting usergroup
    :return: success
    :rtype: boolean
    """
    status_code, res = api.api_delete(
        f"usergroup/{usergroup_id}", subdomain=API_SUBDOMAIN
    )

    if status_code == 200:
        return True
    else:
        raise XQException(message=f"Error deleting Dashboard usergroup: {res}")
