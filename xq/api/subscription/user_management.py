from xq.api.subscription import API_SUBDOMAIN


def authorize_user(api, user, firstName, lastName, newsletter=False, notifications=0):
    payload = {
        "user": user,
        "firstName": firstName,
        "lastName": lastName,
        "newsletter": newsletter,
        "notifications": notifications,
    }

    status_code, auth_token = api.api_post(
        "authorize", data=payload, subdomain=API_SUBDOMAIN
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
        "authorizealias", data={"user": alias}, subdomain=API_SUBDOMAIN
    )

    return auth_token
