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

    status_code, res = api.api_post("usergroup", json=params, subdomain=API_SUBDOMAIN)

    if status_code == 200:
        return res
    else:
        raise XQException(message=f"Error creating Dashboard usergroup: {res}")


def get_usergroup(api, usergroup_id: int = None, name: str = None):
    """get usergroup(s) by id, by name, or all groups

    :param api: XQAPI instance
    :type api: XQAPI
    :param usergroup_id: id of usergroup, defaults to None
    :type usergroup_id: int, optional
    :param name: name of usergroup to search for, defaults to None
    :type name: str, optional
    :raises XQException: error getting usergroup
    :return: usergroup(s)
    :rtype: dict
    """
    endpoint = "usergroup"

    if usergroup_id:
        endpoint = f"{endpoint}/{usergroup_id}"

    status_code, res = api.api_get(endpoint, subdomain=API_SUBDOMAIN)

    if status_code == 200:
        if name and not usergroup_id:
            groups = res.get("groups", res if isinstance(res, list) else [])
            matches = [g for g in groups if g.get("name") == name]
            if not matches:
                raise XQException(message=f"No usergroup found with name: {name}")
            return matches[0] if len(matches) == 1 else matches
        return res
    else:
        raise XQException(message=f"Error getting Dashboard usergroup: {res}")


def update_usergroup(api, usergroup_id: int, name: str, members: List[str]):
    """update a usergroup by id
    WARNING: PATCH and PUT not supported by API

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
    params = {"members": members, "name": name}

    status_code, res = api.api_patch(
        f"usergroup/{usergroup_id}", json=params, subdomain=API_SUBDOMAIN
    )

    if status_code == 204:
        return res
    else:
        raise XQException(message=f"Error updating Dashboard usergroup: {res}")
    

def add_usergroup_members(api, usergroup_id: int = None, name: str = None, members=None):
    """add one or more members to an existing usergroup

    Fetches the current group, merges in the new members, and patches the result.

    :param api: XQAPI instance
    :type api: XQAPI
    :param usergroup_id: id of usergroup, defaults to None
    :type usergroup_id: int, optional
    :param name: name of usergroup (alternative to usergroup_id), defaults to None
    :type name: str, optional
    :param members: member email or list of member emails to add
    :type members: Union[str, List[str]]
    :raises XQException: error adding members to usergroup
    :return: updated usergroup
    :rtype: object
    """
    if not usergroup_id and not name:
        raise XQException(message="Either usergroup_id or name must be provided")
    if not members:
        raise XQException(message="members must be provided")
    if isinstance(members, str):
        members = [members]

    # Fetch existing group to get current members and merge new members avoiding duplicates
    existing = get_usergroup(api, usergroup_id=usergroup_id, name=name)
    if isinstance(existing, list):
        raise XQException(message=f"Multiple usergroups found with name: {name}")
    if usergroup_id is None:
        usergroup_id = existing["id"]
    raw_members = existing.get("members", [])
    existing_members = [
        m["address"] if isinstance(m, dict) else m
        for m in raw_members
        if not isinstance(m, dict) or m.get("kind") == "address"
    ]

    merged = list(set(existing_members + members))

    params = {"members": merged}

    status_code, res = api.api_patch(
        f"usergroup/{usergroup_id}", json=params, subdomain=API_SUBDOMAIN
    )

    if status_code == 204:
        return res
    else:
        raise XQException(message=f"Error adding members to Dashboard usergroup: {res}")


def remove_usergroup_members(api, usergroup_id: int = None, name: str = None, members=None):
    """remove one or more members from an existing usergroup

    Fetches the current group, removes the specified members, and patches the result.

    :param api: XQAPI instance
    :type api: XQAPI
    :param usergroup_id: id of usergroup, defaults to None
    :type usergroup_id: int, optional
    :param name: name of usergroup (alternative to usergroup_id), defaults to None
    :type name: str, optional
    :param members: member email or list of member emails to remove
    :type members: Union[str, List[str]]
    :raises XQException: error removing members from usergroup
    :return: updated usergroup
    :rtype: object
    """
    if not usergroup_id and not name:
        raise XQException(message="Either usergroup_id or name must be provided")
    if not members:
        raise XQException(message="members must be provided")
    if isinstance(members, str):
        members = [members]

    # Fetch existing group to get current members and remove specified members
    existing = get_usergroup(api, usergroup_id=usergroup_id, name=name)
    if isinstance(existing, list):
        raise XQException(message=f"Multiple usergroups found with name: {name}")
    if usergroup_id is None:
        usergroup_id = existing["id"]
    raw_members = existing.get("members", [])
    existing_members = [
        m["address"] if isinstance(m, dict) else m
        for m in raw_members
        if not isinstance(m, dict) or m.get("kind") == "address"
    ]

    updated = [m for m in existing_members if m not in members]

    params = {"members": updated}

    status_code, res = api.api_patch(
        f"usergroup/{usergroup_id}", json=params, subdomain=API_SUBDOMAIN
    )

    if status_code == 204:
        return res
    else:
        raise XQException(message=f"Error removing members from Dashboard usergroup: {res}")


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

    if status_code == 204:
        return True
    else:
        raise XQException(message=f"Error deleting Dashboard usergroup: {res}")
