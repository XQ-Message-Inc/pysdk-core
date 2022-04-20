from xq.exceptions import XQException
from xq.api.manage import API_SUBDOMAIN
from xq.config import DASHBOARD_API_KEY


def dashboard_login(api, email: str = None, password: str = None, method: int = 1):
    """log a given user into their dashboard account
    https://xq.stoplight.io/docs/xqmsg/b3A6NDEyMDYwMDM-login-to-the-dashboard

    :param api: XQAPI instance
    :type api: XQAPI
    :param email: email address of authenticating user, defaults to None
    :type email: str, optional
    :param password: password for user account, defaults to None
    :type password: str, optional
    :param method: authentication method (0 = user/password, 1 = OAuth Token), defaults to 1
    :type method: int, optional
    :raises XQException: authentication error with request
    :return: user access token
    :rtype: string
    """
    if method == 0:
        if not (email and password):
            raise XQException(message=f"Credential auth requested, but not provided")

        payload = {"email": email, "pwd": password, "method": 0}

    elif method == 1:
        # oauth
        payload = {"pwd": DASHBOARD_API_KEY, "method": 1}

    else:
        # unsuported method
        raise XQException(message=f"Unsupported authentication method")

    api.headers.update(
        {"api-key": DASHBOARD_API_KEY}
    )  # dashboard api token needs to be set in the header

    status_code, res = api.api_post("login", json=payload, subdomain=API_SUBDOMAIN)

    if status_code == 200:
        return res
    else:
        raise XQException(message=f"Error authenticating to Dashboard: {res}")
