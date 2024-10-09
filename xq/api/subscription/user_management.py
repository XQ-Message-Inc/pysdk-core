from xq.api.subscription import API_SUBDOMAIN
from xq.api.manage import announce_device
from xq.algorithms.aes_encryption import AESEncryption
from xq.exceptions import XQException
from xq.config import XQ_LOCATOR_KEY
import base64
import json

def authorize_user(
    api,
    user_email: str,
    firstName: str,
    lastName: str,
    newsletter=False,
    notifications=0,
):
    """request pre-auth token for a given email address, this token will need to be exchanged for an access token
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
    :return: pre-aut token, which can be exchanged for an access token
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


def authorize_alias(api, user_email: str, firstName: str, lastName: str):
    """request an access token for the given user information
    https://subscription.xqmsg.net/v2/authorizealias

    :param api: XQAPI instance
    :type api: XQAPI
    :param user_email: email address of user requesting access token
    :type user_email: str
    :param firstName: first name of user
    :type firstName: str
    :param lastName: last name of user
    :type lastName: str
    :return: access token
    :rtype: str
    """
    status_code, auth_token = api.api_post(
        "authorizealias",
        json={"user": user_email, "firstName": firstName, "lastName": lastName},
        subdomain=API_SUBDOMAIN,
    )

    # update auth header to use new bearer token
    api.headers.update({"authorization": f"Bearer {auth_token}"})

    if str(status_code).startswith("20"):
        return auth_token
    else:
        return False
    
def authorize_device(
    api,
    device: str,
    business_id: str = None
):
    """request pre-auth token for a given email address, this token will need to be exchanged for an access token
    https://xq.stoplight.io/docs/xqmsg/b3A6NDA5MDAxNDE-request-access-for-a-user

    :param api: XQAPI instance
    :type api: XQAPI
    :param user_email: device name requesting access token
    :type user_email: str
    :param newsletter: subscribe to newsletter, defaults to False
    :type newsletter: bool, optional
    :param notifications: notification level: 0 = No Notifications, 1 = Receive Usage Reports, 2 = Receive Tutorials, 3 = Receive Both, defaults to 0
    :type notifications: int, optional
    :return: pre-aut token, which can be exchanged for an access token
    :rtype: str
    """
    if business_id == None :
        raise XQException(message=f"Please provide a business_id")
        return False
    
    status_code, encrypted_payload = api.api_post(
        f"authorize/trusted/{business_id}",
        json={
            "device": device,
            "ver": 3,
            "roaming": True,
        },
        subdomain=API_SUBDOMAIN,
    )

    if status_code == 200:
        payload = base64.b64decode(encrypted_payload)
        
        AES = AESEncryption(api.locator_key.encode())

        decrypted_data = AES.decrypt(payload, api.locator_key.encode())
        
        data = json.loads(decrypted_data)

        # update auth header to use new bearer token
        api.headers.update({"authorization": f"Bearer {data.get('access_token')}"})

        # Announce the device to register it in the dashboard.
        status_code= announce_device(api, afirst=device)

        return data.get('access_token')
    else:
        return False
