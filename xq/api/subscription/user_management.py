from xq.api.subscription import API_SUBDOMAIN


def authorize_user(
    api,
    user_email: str,
    firstName: str,
    lastName: str,
    newsletter=False,
    notifications=0,
):
    """request access token for a given email address
    https://xq.stoplight.io/docs/xqmsg/b3A6NDA5MDAxNDE-request-access-for-a-user

    :param api: XQAPI instance
    :type api: XQAPI
    :param user_email: email address of user requesting access token
    :type user_email: str
    :param firstName: first name of user
    :type firstName: str
    :param lastName: last name of user
    :type lastName: str
    :param newsletter: subscribe to newsletter, defaults to False
    :type newsletter: bool, optional
    :param notifications: notification level: 0 = No Notifications, 1 = Receive Usage Reports, 2 = Receive Tutorials, 3 = Receive Both, defaults to 0
    :type notifications: int, optional
    :return: access token
    :rtype: str
    """
    status_code, auth_token = api.api_post(
        "authorize",
        json={
            "user": user_email,
            "firstName": firstName,
            "lastName": lastName,
            "newsletter": newsletter,
            "notifications": notifications,
        },
        subdomain=API_SUBDOMAIN,
    )

    # update auth header to use new bearer token
    api.headers.update({"authorization": f"Bearer {auth_token}"})

    if status_code == 200:
        return auth_token
    else:
        return False


def authorize_alias(api, alias):
    # TODO: build authorizealias functionality
    status_code, auth_token = api.api_post(
        "authorizealias", json={"user": alias}, subdomain=API_SUBDOMAIN
    )

    return auth_token
