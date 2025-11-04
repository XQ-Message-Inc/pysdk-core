from xq.exceptions import XQException
from xq.api.subscription import API_SUBDOMAIN


def create_and_store_packet(
    api,
    recipients: list,
    expires_period: int = 24,
    time_unit: str = "h",
    key: bytes = None,
    type: int|str = "Email",
    subject: str = "meta subject",
    title: str = None,
    labels: list = None
):
    """creates an encrypted packet from a secret key
    https://xqmsg.com/docs/delta/#tag/key-management/post/v3/packet/add

    :param api: XQAPI instance
    :type api: XQAPI
    :param recipients: list of emails to grant access to
    :type recipients: list
    :param expires_period: packet validation time in hours, defaults to 24
    :type expires_period: int, optional
    :param time_unit: packet validation time in hours, defaults to 24
    :type time_unit: str, h d m s
    :param key: secret key to encrypt, defaults to None
    :type key: bytes, optional
    :raises XQException: failed packet creation
    :return: api response, the encrypted packet
    :rtype: text
    """

    meta = {"subject": subject}
    if title:
        meta["title"] = title
    if labels:
        meta["labels"] = labels
    payload = {
        "meta": meta,
        "type": type,
        "recipients": recipients,
        "expires": str(expires_period),
        "timeUnit": time_unit,
        "key": key.decode("utf-8") if isinstance(key, bytes) else key,
    }

    status_code, res = api.api_post("packet/add", json=payload, subdomain=API_SUBDOMAIN)
    if status_code == 200:
        return res
    else:
        raise XQException(message=f"Packet creation failed: {res}")

def create_and_store_packets(
        api,
        recipients: list,
        expires_period: int = 24,
        time_unit: str = "h",
        keys: list = None,
        type: int|str = "Email",
        subject: str = "meta subject",
        title: str = None,
        labels: list = None
):
    """creates an encrypted packet from a secret key
  https://xqmsg.com/docs/delta/#tag/key-management/post/v3/packet/add

    :param api: XQAPI instance
    :type api: XQAPI
    :param recipients: list of emails to grant access to
    :type recipients: list
    :param expires_period: packet validation time in hours, defaults to 24
    :type expires_period: int, optional
    :param time_unit: packet validation time in hours, defaults to 24
    :type time_unit: str, h d m s
    :param key: secret key to encrypt, defaults to None
    :type key: bytes, optional
    :raises XQException: failed packet creation
    :return: api response, list of dicts with key and locator
    :rtype: dict
    """

    meta = {"subject": subject}
    if title:
        meta["title"] = title
    if labels:
        meta["labels"] = labels
    payload = {
        "meta": meta,
        "type": type,
        "recipients": recipients,
        "expires": str(expires_period),
        "timeUnit": time_unit,
        "keys": [key.decode("utf-8") if isinstance(key, bytes) else key for key in keys]
    }

    status_code, res = api.api_post("packet/add", json=payload, subdomain=API_SUBDOMAIN)
    if status_code == 200:
        return res
    else:
        raise XQException(message=f"Packet creation failed: {res}")
    
