from xq.exceptions import XQException
from xq.api.subscription import API_SUBDOMAIN


def create_packet(api, recipients: list, expires_hours: int = 24, key: bytes = None):
    """creates an encrypted packet from a secret key
    https://xq.stoplight.io/docs/xqmsg/b3A6NDA5MDQ5MTY-create-a-new-key-packet

    :param api: XQAPI instance
    :type api: XQAPI
    :param recipients: list of emails to grant access to
    :type recipients: list
    :param expires_hours: packet validation time in hours, defaults to 24
    :type expires_hours: int, optional
    :param key: secret key to encrypt, defaults to None
    :type key: bytes, optional
    :raises XQException: failed packet creation
    :return: api response, the encrypted packet
    :rtype: text
    """
    payload = {
        "recipients": recipients,
        "expires": expires_hours,
        "key": key.decode("utf-8"),
    }
    status_code, res = api.api_post("packet", json=payload, subdomain=API_SUBDOMAIN)

    if status_code == 200:
        return res
    else:
        raise XQException(message=f"Packet creation failed: {res}")


# TODO: not needed
# def create_and_save(api, encrypted_key_packet:bytes, expires_hours=24):
#     """https://xq.stoplight.io/docs/xqmsg/b3A6NDA5MjQ1MjE-create-and-save-a-new-key-packet"""
#     payload = {
#         "expires": expires_hours,
#         "key": encrypted_key_packet,
#     }
#     status_code, res = api.api_post("packet/add", json=payload, subdomain=API_SUBDOMAIN)

#     if status_code == 200:
#         return res
#     else:
#         raise XQException(message=f"Packet storage failed: {res}")
