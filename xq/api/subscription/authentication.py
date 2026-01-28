from xq.exceptions import SDKConfigurationException, XQException
from xq.api.subscription import API_SUBDOMAIN


def validate_api_key(api):
    """static method for validating provided API keys
    https://xqmsg.com/docs/delta/#tag/api-key-management/get/v3/apikey

    :param api: XQAPI instance
    :type api: XQAPI
    :raises SDKConfigurationException: exception for invalid keys
    :raises SDKConfigurationException: exception for http errors
    :return: api response
    :rtype: str OR json
    """
    status_code, res = api.api_get("apikey", subdomain=API_SUBDOMAIN)

    if status_code == 200:
        return res
    if status_code == 401:
        raise SDKConfigurationException(message="The provided API Key is not valid")
    else:
        raise SDKConfigurationException(
            message=f"Failed to verify API key, error: {status_code} - {res}"
        )


def code_validate(api, pin: int):
    """validate the provided 2FA pin
    https://xqmsg.com/docs/delta/#tag/authentication-management/get/v3/login/verify

    :param api: XQAPI instance
    :type api: XQAPI
    :param pin: 2FA code
    :type pin: int
    :raises XQException: invalid pin
    :return: isvalid? boolean response
    :rtype: bool
    """
    return api.login_verify(pin)


def exchange_key(api):
    """exchange pre-auth token for an access token, and update headers accordingly
    https://xqmsg.com/docs/delta/#tag/authentication-management/get/v3/login/exchange

    :param api: XQAPI instance
    :type api: XQAPI
    :raises XQException: key exchange failure
    :return: success? boolean
    :rtype: bool
    """
    params = {"code": api.headers["code"]}
    status_code, auth_token = api.api_get(
        "login/exchange", params=params, subdomain=API_SUBDOMAIN
    )

    if status_code == 200:
        api.headers.update({"authorization": f"Bearer {auth_token}"})
        return True
    else:
        raise XQException(message=f"Key Exchange creation failed: {auth_token}")

