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


def exchange_key(api, business_id: str = None, selector: bool = False):
    """exchange pre-auth token for an access token, and update headers accordingly
    https://xq.stoplight.io/docs/xqmsg/b3A6NDA5Mzc1NjA-exchange-for-access-token

    :param api: XQAPI instance
    :type api: XQAPI
    :param business_id: optional business ID to associate with the exchange
    :type business_id: str, optional
    :param selector: selector flag for the exchange, defaults to False
    :type selector: bool, optional
    :raises XQException: key exchange failure
    :return: success? boolean
    :rtype: bool
    """
    params = {
        "selector": selector,
        **({} if business_id is None else {"b": business_id}),
    }
    
    status_code, auth_token = api.api_get(
        "exchange", params=params, subdomain=API_SUBDOMAIN
    )

    if status_code == 200:
        api.headers.update({"authorization": f"Bearer {auth_token}"})
        api.set_api_auth_token(auth_token)
        return True
    else:
        raise XQException(message=f"Key Exchange creation failed: {auth_token}")
