from xq.exceptions import SDKConfigurationException, XQException
from xq.api.quantum import API_SUBDOMAIN


def get_entropy(api, length=2, type="uint8"):
    """Generate quantum entropy from XQ with the provided number of entropy bits, returns as array of type
    https://xqmsg.com/docs/delta/#tag/entropy-configuration/get/v3/qrng

    :param api: XQAPI instance
    :type api: XQAPI
    :param length: length of  of entropy bits to fetch, defaults to 2
    :type length: int, optional
    :param type : type of array to return. Values unint8, hex8 defaults to uint8
    :type type: str, optional.
    :raises SDKConfigurationException:  exception for http errors
    :return: entropy
    :rtype: base64 string
    """
    status_code, res = api.api_get(
        "qrng", params={"length": length, "type": type}, subdomain=API_SUBDOMAIN
    )

    if status_code == 200:
        return res["data"]
    else:
        raise SDKConfigurationException(
            message=f"Failed to retrieve entropy, error: {status_code} - {res}"
        )
