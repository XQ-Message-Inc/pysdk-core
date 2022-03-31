import urllib
from xq.exceptions import XQException

from xq.api.validation import API_SUBDOMAIN


def get_packet(api, locator_token):
    # https://xq.stoplight.io/docs/xqmsg/b3A6NDA5NDY4ODE-retrieve-a-key-with-its-token
    status_code, res = api.api_get(
        f"key/{urllib.parse.quote_plus(locator_token)}", subdomain=API_SUBDOMAIN
    )

    if status_code == 200:
        return res
    else:
        raise XQException(message=f"Packet retrieval failed: {res}")
