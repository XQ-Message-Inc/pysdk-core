import urllib
from xq.exceptions import XQException


def get_packet(api, locator_token):
    status_code, res = api.api_get(f"key/{urllib.parse.quote_plus(locator_token)}")

    if status_code == 200:
        return res
    else:
        raise XQException(message=f"Packet retrieval failed: {res}")
