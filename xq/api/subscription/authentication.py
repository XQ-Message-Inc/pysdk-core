from xq.exceptions import SDKConfigurationException, XQException
from xq.api.subscription import API_SUBDOMAIN


def validate_api_key(api):
    """static method for validating provided API keys

    :raises SDKConfigurationException: exception for invalid keys
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
    status_code, res = api.api_get(
        "codevalidation", params={"pin": pin}, subdomain=API_SUBDOMAIN
    )

    if str(status_code).startswith("20"):
        return True
    else:
        raise XQException(message="The provided pin is incorrect")


def exchange_key(api):
    status_code, auth_token = api.api_get("exchange", subdomain=API_SUBDOMAIN)

    if status_code == 200:
        api.headers.update({"authorization": f"Bearer {auth_token}"})
        return True
    else:
        raise XQException(message=f"Key Exchange creation failed: {auth_token}")
