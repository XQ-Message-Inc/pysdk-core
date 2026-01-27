from xq.exceptions import XQException
from xq.api.manage import API_SUBDOMAIN
from xq.config import DASHBOARD_API_KEY
import urllib.parse

def get_communication_by_locator_token(api, locator_token: str):
    """Get a single communication by its locator token.
    https://xq.stoplight.io/docs/xqmsg/005edb8a9ec2b-get-communication-by-its-locator-token

    :param api: XQAPI instance
    :type api: XQAPI
    :raises XQException: invalid access token
    :return: validated
    :rtype: boolean
    """
    api.headers.update(
        {"api-key": DASHBOARD_API_KEY}
    )  # dashboard api token needs to be set in the header

    status_code, res = api.api_get(
        f"communication/{urllib.parse.quote_plus(locator_token)}", subdomain=API_SUBDOMAIN
    )

    if status_code == 200:
        return res
    else:
        raise XQException(message=f"Communication retrieval failed: {res}")
    
def add_labels_to_locator_token(api, locator_token: str, labels: list):
    """Add labels to a communication by its locator token.
    https://xq.stoplight.io/docs/xqmsg/1f9bc1713a7cd-create-and-save-a-new-key-packet

    :param api: XQAPI instance
    :type api: XQAPI
    :raises XQException: invalid access token
    :return: validated
    :rtype: boolean
    """
    api.headers.update(
        {"api-key": DASHBOARD_API_KEY}
    ) 

    payload = {
        "labels": labels
    }

    status_code, res = api.api_patch(
        f"communication/{urllib.parse.quote_plus(locator_token)}/labels", json=payload, subdomain=API_SUBDOMAIN
    )

    print(status_code, res)

    if status_code == 200 or status_code == 204:
        return res
    else:
        raise XQException(message=f"Adding labels failed: {res}")