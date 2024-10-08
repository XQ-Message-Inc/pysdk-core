from xq.exceptions import XQException
from xq.api.manage import API_SUBDOMAIN
from xq.config import DASHBOARD_API_KEY, API_KEY


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

    # NOTE: password authentication to dashboard is not currently suppored by the API
    if password:
        payload["pwd"] = password

    api.headers.update(
        {"api-key": DASHBOARD_API_KEY}
    )  # dashboard api token needs to be set in the header

    status_code, res = api.api_post("signup", json=payload, subdomain=API_SUBDOMAIN)

    if status_code == 204:
        return res
    elif status_code == 409:
        # already registered
        return res
    else:
        raise XQException(message=f"Error registering Dashboard user: {res}")


def send_login_link(api, email: str, host: str = None):
    """send login magic link to a users email for Dashboard authentication
    https://xq.stoplight.io/docs/xqmsg/5cde236a164ba-send-login-magic-link-to-a-user

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

    api.headers.update(
        {"api-key": DASHBOARD_API_KEY}
    )  # dashboard api token needs to be set in the header

    status_code, res = api.api_post("login/link", json=payload, subdomain=API_SUBDOMAIN)

    if status_code == 204:
        return True
    else:
        raise XQException(message=f"Error sending Dashboard magic link: {res}")


def dashboard_login(
    api, password: str, email: str = None, method: int = 1, workspace: str = None
):
    """log a given user into their dashboard account
    https://xq.stoplight.io/docs/xqmsg/b3A6NDEyMDYwMDM-login-to-the-dashboard

    :param api: XQAPI instance
    :type api: XQAPI
    :param email: email address of authenticating user, defaults to None
    :type email: str, optional
    :param password: password or magic link for user account
    :type password: str
    :param method: authentication method (0 = user/password, 1 = OAuth Token), defaults to 0
    :type method: int, optional
    :param workspace: the account workspace. This field is deprecated and should not be used., defaults to None
    :type workspace: string, optional - DEPRECATED
    :raises XQException: authentication error with request
    :return: user access token
    :rtype: string
    """
    if "?access_token=" not in password:
        if method == 0:
            # NOTE: password authentication to dashboard is not currently suppored by the API
            if not (email and password):
                raise XQException(
                    message=f"Credential auth requested, but not provided"
                )
            payload = {"email": email, "pwd": password, "method": 0}
        elif method == 1:  # oauth
            payload = {"pwd": password, "method": 1}
        else:  # unsuported method
            raise XQException(message=f"Unsupported authentication method")
        if workspace:
            payload["workspace"] = workspace

        api.headers.update(
            {"api-key": DASHBOARD_API_KEY}
        )  # dashboard api token needs to be set in the header

        status_code, auth_token = api.api_post(
            "login", json=payload, subdomain=API_SUBDOMAIN
        )
    else:
        auth_token = password.split("?access_token=", 1)[1].split("&token=")[0]
        status_code = 200

    if status_code == 200:
        api.headers.update(
            {"authorization": f"Bearer {auth_token}"}
        )  # update auth header with Dashboard token
        return True
    else:
        raise XQException(message=f"Error authenticating to Dashboard: {auth_token}")


def login_verify(api):
    """verify a user's login and exchange fake auth_token for a real auth_token
    :param api: XQAPI instance
    :type api: XQAPI
    :raises XQException: unable to verify login
    :return: validated
    :rtype: boolean
    """
    api.headers.update(
        {"api-key": DASHBOARD_API_KEY}
    )  # dashboard api token needs to be set in the header

    status_code, res = api.api_get(
        "login/verify?request=default", subdomain=API_SUBDOMAIN
    )

    if status_code == 200:
        api.headers.update(
            {"authorization": f"Bearer {res}"}
        )  # update auth header with Dashboard token
        return True
    else:
        raise XQException(message=f"Unable to verify login: {res}")


def validate_access_token(api):
    """validate that the set access_token is valid for the dashboard
    https://xq.stoplight.io/docs/xqmsg/f260b4a8eb1ea-validate-an-access-token

    :param api: XQAPI instance
    :type api: XQAPI
    :raises XQException: invalid access token
    :return: validated
    :rtype: boolean
    """
    api.headers.update(
        {"api-key": DASHBOARD_API_KEY}
    )  # dashboard api token needs to be set in the header

    status_code, res = api.api_get("session", subdomain=API_SUBDOMAIN)

    if status_code == 204:
        return True
    else:
        raise XQException(message=f"Unable to validate access token: {res}")
    
def announce_device(api, afirst: str = "", alast: str = "", aphone: str = ""):
    """static method for announcing the trusted device to the dashboard, registering
    the device as a team member.

    :param api: XQAPI instance
    :type api: XQAPI
    :param afirst (optional): The name of the device
    :type afirst: str
    :param alast (optional): The last name of the device
    :type alast: str
    :param aphone (optional): The phone number of the device
    :type aphone: str
    :return: api response status code
    :rtype: str
    """
    api.headers.update(
        {"api-key": DASHBOARD_API_KEY}
    )  # dashboard api token needs to be set in the header

    payload = {
        "afirst": afirst,
        "alast": alast,
        'aphone': aphone 
    }

    status_code = api.api_post("trusted/announce", json=payload, subdomain=API_SUBDOMAIN)
    
    api.headers.update(
        {"api-key": API_KEY}
    )

    if status_code == 200 or 204:
        return status_code
    if status_code == 401:
        raise XQException(message="The provided API Key is not valid")
    else:
        raise XQException(
            message=f"Failed to verify API key, error: {status_code}"
        )
