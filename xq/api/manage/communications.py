from xq.exceptions import XQException
from xq.api.manage import API_SUBDOMAIN
import urllib.parse

def get_communication_by_locator_token(api, locator_token: str):
    """Get a single communication by its locator token.
    https://xqmsg.com/docs/delta/#tag/communication-discovery/get/v3/communication/{cursor}

    :param api: XQAPI instance
    :type api: XQAPI
    :raises XQException: invalid access token
    :return: validated
    :rtype: boolean
    """
    status_code, res = api.api_get(
        f"communication/{urllib.parse.quote_plus(locator_token)}", subdomain=API_SUBDOMAIN
    )

    if status_code == 200:
        return res
    else:
        raise XQException(message=f"Communication retrieval failed: {res}")

def add_labels_to_locator_token(api, locator_token: str, labels: list):
    """Add labels to a communication by its locator token.

    :param api: XQAPI instance
    :type api: XQAPI
    :raises XQException: invalid access token
    :return: validated
    :rtype: boolean
    """

    payload = {
        "labels": labels
    }

    status_code, res = api.api_patch(
        f"communication/{urllib.parse.quote_plus(locator_token)}/labels", json=payload, subdomain=API_SUBDOMAIN
    )

    if status_code == 204:
        return res
    else:
        raise XQException(message=f"Adding labels failed: {res}")