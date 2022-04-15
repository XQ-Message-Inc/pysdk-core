import urllib
from typing import List

from xq.exceptions import XQException
from xq.api.validation import API_SUBDOMAIN


def get_packet(api, locator_token: str):
    """fetch key with provided locator token
    https://xq.stoplight.io/docs/xqmsg/b3A6NDA5NDY4ODE-retrieve-a-key-with-its-token

    :param api: XQPAI instance
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


def add_packet(api, encrypted_key_packet: bytes):
    """upload an encrypted key packet to XQ
    https://xq.stoplight.io/docs/xqmsg/b3A6NDE4NTY2NDE-add-a-new-key-packet

    :param api: XQAPI instance
    :type api: XQAPI
    :param encrypted_key_packet: key packet to upload
    :type encrypted_key_packet: bytes
    :raises XQException: packet creation failed
    :return: locator token to access key later
    :rtype: string
    """
    status_code, res = api.api_post(
        "packet", data=encrypted_key_packet, subdomain=API_SUBDOMAIN
    )

    if status_code == 200:
        return res
    else:
        raise XQException(message=f"Packet creation failed: {res}")


def revoke_packet(api, locator_token: str):
    """revoke a key packet with the provided locator token
    https://xq.stoplight.io/docs/xqmsg/b3A6NDA5NDY4ODI-revoke-access-to-a-key

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


def grant_users(api, locator_token: str, recipients: List[str]):
    """grant a list of recipients access to a given token

    :param api: XQAPI instance
    :type api: XQAPI
    :param locator_token: url encoded locator token
    :type locator_token: str
    :param recipients: list of user emails to grant
    :type recipients: List[str]
    :raises XQException: access grant failed
    :return: success
    :rtype: boolean
    """
    status_code, res = api.api_post(
        f"grant/{urllib.parse.quote_plus(locator_token)}",
        json={"recipients": recipients},
        subdomain=API_SUBDOMAIN,
    )

    if str(status_code).startswith("20"):
        return True
    else:
        raise XQException(message=f"Packet access grant failed: {res}")


def revoke_users(api, locator_token: str, recipients: List[str]):
    """revoke a list of recipents from accessing a given token

    :param api: XQAPI instance
    :type api: XQAPI
    :param locator_token: url encoded locator token
    :type locator_token: str
    :param recipients: list of user emails to revoke
    :type recipients: List[str]
    :raises XQException: acces revoke failed
    :return: success
    :rtype: boolean
    """
    status_code, res = api.api_patch(
        f"revoke/{urllib.parse.quote_plus(locator_token)}",
        json={"recipients": recipients},
        subdomain=API_SUBDOMAIN,
    )

    if str(status_code).startswith("20"):
        return True
    else:
        raise XQException(message=f"Packet access grant failed: {res}")
