import urllib.parse
from typing import List
from xq.exceptions import XQException
from xq.api.validation import API_SUBDOMAIN


def get_packet(api, locator_token: str):
    """fetch key with provided locator token
    https://xqmsg.com/docs/delta/#tag/key-management/get/v3/key/{token}

    :param api: XQAPI instance
    :type api: XQAPI
    :param locator_token: url encoded locator token
    :type locator_token: str
    :raises XQException: packet retrieval failed
    :return: key
    :rtype: string
    """
    status_code, res = api.api_get(
        f"key/{urllib.parse.quote_plus(locator_token)}", subdomain=API_SUBDOMAIN
    )

    if status_code == 200:
        return res
    else:
        raise XQException(message=f"Packet retrieval failed: {res}")


def get_packets(api, locator_tokens: List[str]):
    """fetch keys with provided locator tokens
    https://xqmsg.com/docs/delta/#tag/key-management/post/v3/keys

    :param api: XQAPI instance
    :type api: XQAPI
    :param locator_tokens: url encoded locator tokens
    :type locator_tokens: List[str]
    :raises XQException: packet retrieval failed
    :return: dict of locators and keys
    :rtype: dict
    """
    status_code, res = api.api_post(
        f"keys", subdomain=API_SUBDOMAIN, json=locator_tokens
    )

    if status_code == 200:
        return res
    else:
        raise XQException(message=f"Packet retrieval failed: {res}")


def revoke_packet(api, locator_token: str):
    """revoke a key packet with the provided locator token
    https://xqmsg.com/docs/delta/#tag/key-management/delete/v3/key/{token}

    :param api: XQAPI instance
    :type api: XQAPI
    :param locator_token: url encoded locator token
    :type locator_token: str
    :raises XQException: packet revokation failed
    :return: success
    :rtype: bool
    """
    status_code, res = api.api_delete(
        f"key/{urllib.parse.quote_plus(locator_token)}", subdomain=API_SUBDOMAIN
    )

    if str(status_code).startswith("20"):
        return True
    else:
        raise XQException(message=f"Packet deletion failed: {res}")


def grant_users(api, locator_token: str, recipients: List[str], alias_access=False):
    """grant a list of recipients access to a given token
    https://xqmsg.com/docs/delta/#tag/key-management/post/v3/key/{token}/recipients

    :param api: XQAPI instance
    :type api: XQAPI
    :param locator_token: url encoded locator token
    :type locator_token: str
    :param recipients: list of user emails to grant
    :type recipients: List[str]
    :param alias_access: grant the user access for alias (non-MFA)
    :type alias_access: Boolean
    :raises XQException: access grant failed
    :return: success
    :rtype: boolean
    """
    if alias_access:
        recipients = [f"{email}@alias.local" for email in recipients]

    status_code, res = api.api_post(  # documentation says PATCH, but supports POST
        f"key/{urllib.parse.quote_plus(locator_token)}/recipients",
        json={"recipients": recipients},
        subdomain=API_SUBDOMAIN,
    )

    if str(status_code).startswith("20"):
        return True
    else:
        raise XQException(message=f"Packet access grant failed: {res}")


def revoke_users(api, locator_token: str, recipients: List[str], alias_access=False):
    """revoke a list of recipents from accessing a given token
    https://xqmsg.com/docs/delta/#tag/key-management/delete/v3/key/{token}/recipients

    :param api: XQAPI instance
    :type api: XQAPI
    :param locator_token: url encoded locator token
    :type locator_token: str
    :param recipients: list of user emails to revoke
    :type recipients: List[str]
    :param alias_access: grant the user access for alias (non-MFA)
    :type alias_access: Boolean
    :raises XQException: acces revoke failed
    :return: success
    :rtype: boolean
    """
    if alias_access:
        recipients = [f"{email}@alias.local" for email in recipients]

    status_code, res = api.api_delete(
        f"key/{urllib.parse.quote_plus(locator_token)}/recipients",
        json={"recipients": recipients},
        subdomain=API_SUBDOMAIN,
    )

    if str(status_code).startswith("20"):
        return True
    else:
        raise XQException(message=f"Packet access revoke failed: {res}")
