from xq.exceptions import SDKConfigurationException, XQException
from xq.api.quantum import API_SUBDOMAIN


def get_entropy(api, entropy_bits=2):
    """Generate quantum entropy from XQ with the provided number of entropy bits, returns as decoded string
    https://xq.stoplight.io/docs/xqmsg/b3A6NDA5MDAxNDY-quantum-generator

    :param api: XQAPI instance
    :type api: XQAPI
    :param entropy_bits: number of entropy bits to fetch, defaults to 2
    :type entropy_bits: int, optional
    :raises SDKConfigurationException:  exception for http errors
    :return: entropy
    :rtype: base64 string
    """
    status_code, res = api.api_get(
        "/", params={"ks": entropy_bits}, subdomain=API_SUBDOMAIN
    )

    if status_code == 200:
        return res
    else:
        raise SDKConfigurationException(
            message=f"Failed to retrieve entropy, error: {status_code} - {res}"
        )
