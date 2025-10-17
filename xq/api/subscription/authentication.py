from xq.exceptions import SDKConfigurationException, XQException
from xq.api.subscription import API_SUBDOMAIN


def validate_api_key(api):
    """static method for validating provided API keys
    https://xq.stoplight.io/docs/xqmsg/b3A6NDExNDU1MDg-check-if-valid-api-key

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
    https://xq.stoplight.io/docs/xqmsg/b3A6NDA5MjQ1MjM-validate-access-request-with-a-pin

    :param api: XQAPI instance
    :type api: XQAPI
    :param pin: 2FA code
    :type pin: int
    :raises XQException: invalid pin
    :return: isvalid? boolean response
    :rtype: bool
    """
    status_code, res = api.api_get(
        "codevalidation", params={"pin": pin}, subdomain=API_SUBDOMAIN
    )

    if str(status_code).startswith("20"):
        return True
    else:
        raise XQException(message="The provided pin is incorrect")


def exchange_key(api, business_id: str = None):
    """exchange pre-auth token for an access token, and update headers accordingly
    https://xq.stoplight.io/docs/xqmsg/b3A6NDA5Mzc1NjA-exchange-for-access-token

    :param api: XQAPI instance
    :type api: XQAPI
    :raises XQException: key exchange failure
    :return: success? boolean
    :rtype: bool
    """
    status_code, auth_token = api.api_get(
        f"exchange?b={business_id}&selector=false", subdomain=API_SUBDOMAIN
    )

    if status_code == 200:
        api.headers.update({"authorization": f"Bearer {auth_token}"})
        return True
    else:
        raise XQException(message=f"Key Exchange creation failed: {auth_token}")
