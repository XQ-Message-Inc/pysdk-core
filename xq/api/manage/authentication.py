import os
from xq.exceptions import XQException
from xq.api.manage import API_SUBDOMAIN


def create_certificate(api, tag: str, fence: list[str] = None, enabled: bool = True, output_dir: str = None,
                       client_key_path: str = None, client_cert_path: str = None, transport_key_path: str = None
                       ):
    """Create a certificate
    https://xqmsg.com/docs/delta/#tag/certificate-management/post/v3/certificate

    :param api: XQ API client instance
    :type api: XQAPI
    :param tag: The identifying tag of the new certificate.
    :type tag: str
    :param fence: List of IPs or locations to require for this certificate.
    :type fence: list[str]
    :param enabled: Specifies if this certificate is enabled or disabled., defaults to True
    :type enabled: boolean
    :param output_dir: optional directory to save certificate files (client.key, client.crt, transport.key), defaults to None
    :type output_dir: str, optional
    :param client_key_path: optional custom path for client key file, overrides output_dir, defaults to None
    :type client_key_path: str, optional
    :param client_cert_path: optional custom path for client certificate file, overrides output_dir, defaults to None
    :type client_cert_path: str, optional
    :param transport_key_path: optional custom path for transport key file, overrides output_dir, defaults to None
    :type transport_key_path: str, optional
    :raises XQException: error generating device certificate
    :return: certificate data containing id, transportKey, clientCert, and clientKey
    :rtype: dict

    """
    if fence is None:
        fence = []

    payload = {
        "tag": tag,
        "geofence": fence,
        "enabled": enabled
    }

    status_code, res = api.api_post(f"certificate", json=payload, subdomain=API_SUBDOMAIN)
    if status_code == 200:
        # Write certificate files if paths are provided
        if output_dir or client_key_path or client_cert_path or transport_key_path:
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
                if not client_key_path:
                    client_key_path = os.path.join(output_dir, "client.key")
                if not client_cert_path:
                    client_cert_path = os.path.join(output_dir, "client.crt")
                if not transport_key_path:
                    transport_key_path = os.path.join(output_dir, "transport.key")

            if client_key_path:
                with open(client_key_path, "w") as f:
                    f.write(res["clientKey"])

            if client_cert_path:
                with open(client_cert_path, "w") as f:
                    f.write(res["clientCert"])

            if transport_key_path:
                with open(transport_key_path, "w") as f:
                    f.write(res["transportKey"])

        return res
    else:
        raise XQException(message=f"Failed creating certificate: {res}")


def delete_certificate(api, id: int):
    """Delete  a certificate
    https://xqmsg.com/docs/delta/#tag/certificate-management/delete/v3/certificate/{id}

    :param api: XQ API client instance
    :type api: XQAPI
    :param id: The id of the certificate to be deleted
    :type id: int
    :return: success
    :rtype: boolean
    """

    api.headers["X-Certificate-ID"] = str(id)
    status_code, res = api.api_delete(
        f"certificate/{id}", subdomain=API_SUBDOMAIN
    )

    if status_code == 204:
        return True
    else:
        raise XQException(message=f"Error deleting certificate{res}")


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
    :return: dict with code
    :rtype: dict
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


def login_alias(api, email: str, ):
    """login automatically  without login link
    https://xqmsg.com/docs/delta/#tag/authentication-management/post/v3/login/alias

    :param api: XQAPI instance
    :type api: XQAPI
    :param email: email address of authenticating user
    :type email: str
    :return: success
    :rtype: boolean
    """

    status_code, auth_token = api.api_post("login/alias", json={"user": email}, subdomain=API_SUBDOMAIN)
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


def get_registered_teams(api):
    """get list of teams the user is a part
    https://xqmsg.com/docs/delta/#tag/team-management/GET/v3/teams/registered

    :param api: XQAPI instance
    :type api: XQAPI
    :raises XQException: error retrieving businesses
    :return: list of businesses
    :rtype: list
    """
    status_code, res = api.api_get("registered", subdomain=API_SUBDOMAIN)

    if status_code == 200:
        return res
    else:
        raise XQException(message=f"Error retrieving businesses: {res}")


def get_team(api):
    """get the team information
    https://xqmsg.com/docs/delta/#tag/team-management/GET/v3/team

    :param api: XQAPI instance
    :type api: XQAPI
    :raises XQException: error retrieving business information
    :return: business information
    :rtype: dict
    """
    status_code, res = api.api_get("team", subdomain=API_SUBDOMAIN)

    if status_code == 200:
        return res
    else:
        raise XQException(message=f"Error retrieving business information: {res}")
