##
# WARNING: THIS IS ALL MADE UP, THERE ARE NO DOCS
#
# Assumed Requirements: Full CRUD on https://dashboard.xqmsg.net/v2/usergroup
##

from xq.exceptions import XQException
from xq.api.manage import API_SUBDOMAIN


def create_usergroup(api):
    payload = {}

    status_code, res = api.api_post("usergroup", json=payload, subdomain=API_SUBDOMAIN)

    if status_code == 200:
        return res
    else:
        raise XQException(message=f"Error creating Dashboard usergroup: {res}")


def get_usergroup(api):
    params = {}

    status_code, res = api.api_get("usergroup", params=params, subdomain=API_SUBDOMAIN)

    if status_code == 200:
        return res
    else:
        raise XQException(message=f"Error getting Dashboard usergroup: {res}")


def update_usergroup(api):
    params = {}

    status_code, res = api.api_put("usergroup", params=params, subdomain=API_SUBDOMAIN)

    if status_code == 200:
        return res
    else:
        raise XQException(message=f"Error updating Dashbaord usergroup: {res}")


def delete_usergroup(api, usergroup_id):
    status_code, res = api.api_delete(
        "usergroup", params={"id": usergroup_id}, subdomain=API_SUBDOMAIN
    )

    if status_code == 200:
        return res
    else:
        raise XQException(message=f"Error deleting Dashboard usergroup: {res}")
