def authorize_user(api, user, firstName, lastName, newsletter=False, notifications=0):
    payload = {
        "user": user,
        "firstName": firstName,
        "lastName": lastName,
        "newsletter": newsletter,
        "notifications": notifications,
    }

    status_code, auth_token = api.api_post("authorize", data=payload)

    # update auth header to use new bearer token
    api.headers["authorization"] = f"Bearer {auth_token}"

    if status_code == 200:
        return auth_token
    else:
        return False


def authorize_alias(api, alias):
    status_code, auth_token = api.api_post("authorizealias", data={"user": alias})

    print(status_code, auth_token)
    return auth_token
