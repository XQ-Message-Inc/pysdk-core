from xq.exceptions import XQException
from xq.api.manage import API_SUBDOMAIN
from xq.config import DASHBOARD_API_KEY


def dashboard_signup(api, email: str, password: str = None, emailOptIn=True):
    """register a new user for XQ Dashboard access
    https://xq.stoplight.io/docs/xqmsg/b3A6NDEyMDYwMDI-self-sign-up

    :param api: XQAPI instance
    :type api: XQAPI
    :param email: email address of registering user
    :type email: str
    :param password: optional password, used for authenticating without email 2FA, defaults to None
    :type password: str, optional
    :param emailOptIn: opt in to email notifications, defaults to True
    :type emailOptIn: bool, optional
    """
    payload = {
        "email": email,
        "optIn": emailOptIn,
        # 'state': ''   # UI only, user tracking
    }

    if password:
        payload["pwd"] = password

    api.headers.update(
        {"api-key": DASHBOARD_API_KEY}
    )  # dashboard api token needs to be set in the header

    status_code, res = api.api_post("signup", json=payload, subdomain=API_SUBDOMAIN)

    if status_code == 200:
        return res
    elif status_code == 409:
        # already registered
        return res
    else:
        raise XQException(message=f"Error registering Dashboard user: {res}")


def dashboard_login(api, email: str = None, password: str = None, method: int = 0):
    """log a given user into their dashboard account
    https://xq.stoplight.io/docs/xqmsg/b3A6NDEyMDYwMDM-login-to-the-dashboard

    :param api: XQAPI instance
    :type api: XQAPI
    :param email: email address of authenticating user, defaults to None
    :type email: str, optional
    :param password: password for user account, defaults to None
    :type password: str, optional
    :param method: authentication method (0 = user/password, 1 = OAuth Token), defaults to 0
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
