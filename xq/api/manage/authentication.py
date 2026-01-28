from xq.exceptions import XQException
from xq.api.manage import API_SUBDOMAIN


def send_login_link(api, email: str, host: str = None):
    """send login magic link to a users email for Dashboard authentication
    https://xqmsg.com/docs/delta/#tag/authentication-management/post/v3/login/link

    :param api: XQAPI instance
    :type api: XQAPI
    :param email: email address of authenticating user
    :type email: str
    :param host: the host domain that login links will target.  if not provided, the default will be used, defaults to None
    :type host: str, optional
    :raises XQException: error sending magic link
    :return: success
    :rtype: boolean
    """
    payload = {"email": email}
    if host:
        payload["host"] = host

    status_code, res = api.api_post("login/link", json=payload, subdomain=API_SUBDOMAIN)
    if status_code == 200:
        api.headers.update({"code": res["code"]})
        return res
    else:
      raise XQException(message=f"Error with status code {status_code} in login/link: {res}")



def login_alias(api, email: str,):
    """login automatically  without login link
    https://xqmsg.com/docs/delta/#tag/authentication-management/post/v3/login/alias

    :param api: XQAPI instance
    :type api: XQAPI
    :param email: email address of authenticating user
    :type email: str
    :return: success
    :rtype: boolean
    """

    status_code, auth_token = api.api_post("login/alias", json={"user":email}, subdomain=API_SUBDOMAIN)
    if status_code == 200:
        api.headers.update({"authorization": f"Bearer {auth_token}"})
        return True
    else:
        raise XQException(message=f"Error in login alias: {auth_token}")


def login_verify(api, pin: str):
    """verify a user's login and exchange fake auth_token for a real auth_token
    https://xqmsg.com/docs/delta/#tag/authentication-management/get/v3/login/verify
    :param api: XQAPI instance
    :type api: XQAPI
    :param pin: pin returned in login
    :type pin: str
    :raises XQException: unable to verify login
    :return: validated
    :rtype: boolean
    """
    params = {"code": api.headers["code"], "pin": pin}
    status_code, res = api.api_get(
        "login/verify", params=params, subdomain=API_SUBDOMAIN
    )

    if status_code == 204:
        api.headers.update(
            {"authorization": f"Bearer {res}"}
        )  # update auth header with Dashboard token
        return True
    else:
        raise XQException(message=f"Unable to verify login: {res}")



def validate_access_token(api):
    """validate that the set access_token is valid for the dashboard


    :param api: XQAPI instance
    :type api: XQAPI
    :raises XQException: invalid access token
    :return: validated
    :rtype: boolean
    """

    status_code, res = api.api_get("session", subdomain=API_SUBDOMAIN)

    if status_code == 204:
        return True
    else:
        raise XQException(message=f"Unable to validate access token: {res}")
