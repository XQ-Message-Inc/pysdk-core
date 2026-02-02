from xq.exceptions import XQException
from xq.api.subscription import API_SUBDOMAIN


def create_and_store_packet(
    api,
    recipients: list,
    expires_period: int = 24,
    time_unit: str = "h",
    key: bytes = None,
    type: str = "Email",
    subject: str = None,
    title: str = None,
    labels: list = None,
    meta: dict = None
):
    """creates an encrypted packet from a secret key
    https://xqmsg.com/docs/delta/#tag/key-management/post/v3/packet/add

    :param api: XQAPI instance
    :type api: XQAPI
    :param recipients: list of emails to grant access to
    :type recipients: list
    :param expires_period: packet validation time in hours, defaults to 24
    :type expires_period: int, optional
    :param time_unit: packet validation expires period time unit, defaults to h
    :type time_unit: str, h d m s
    :param key: secret key to encrypt, defaults to None
    :type key: bytes, optional
    :param type: packet type (applies to all entries), defaults to "Email"
    :type type: str, optional
    :param subject: subject of communication
    :type subject: str
    :param title: title of communication
    :type title: str, optional
    :param labels: list of labels
    :type labels: list, optional
    :param meta: dict of parameters
    :type meta: dict, optional
    :raises XQException: failed packet creation
    :return: api response, the encrypted packet
    :rtype: text
    """
    if not meta:
        meta = {}
    if subject:
        meta["subject"] = subject
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
        type: str = "Email",
        subject: str = None,
        title: str = None,
        labels: list = None,
        meta: dict = None
):
    """creates an encrypted packet from a secret key
  https://xqmsg.com/docs/delta/#tag/key-management/post/v3/packet/add

    :param api: XQAPI instance
    :type api: XQAPI
    :param recipients: list of emails to grant access to
    :type recipients: list
    :param expires_period: packet validation time in hours, defaults to 24
    :type expires_period: int, optional
    :param time_unit: packet validation expires period time unit, defaults to h
    :type time_unit: str, h d m s
    :param keys: list of secret keys to encrypt, defaults to None
    :type keys: list, optional
    :param type: packet type (applies to all entries), defaults to "Email"
    :type type: str, optional
    :param subject: subject of communication
    :type subject: str
    :param title: title of communication
    :type title: str, optional
    :param labels: list of lables
    :type labels: list, optional
    :param meta: dict of parameters
    :type meta: dict, optional
    :raises XQException: failed packet creation
    :return: api response, list of dicts with key and locator
    :rtype: dict
    """

    if not meta:
        meta = {}
    if subject:
        meta["subject"] = subject
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

def create_and_store_packets_batch(
        api,
        keys: list,
        recipients: list,
        metadata_list: list = None,
        expires_period: int = 24,
        time_unit: str = "h",
        type: str = "Database"
):
    """batch insert key packets in bulk for database types
    https://xq.stoplight.io/docs/xqmsg/b3A6NDA5MDQ5MTY-create-a-new-key-packet

    :param api: XQAPI instance
    :type api: XQAPI
    :param keys: list of secret keys to encrypt
    :type keys: list
    :param recipients: list of emails to grant access to (applies to all entries)
    :type recipients: list
    :param metadata_list: list of metadata dicts with title and labels for each key, defaults to None
    :type metadata_list: list, optional
    :param expires_period: packet validation time in hours, defaults to 24
    :type expires_period: int, optional
    :param time_unit: packet validation expires period time unit, defaults to h
    :type time_unit: str, h d m s
    :param type: packet type (applies to all entries), defaults to "database"
    :type type: str, optional
    :raises XQException: failed batch packet creation
    :return: api response with created packets
    :rtype: dict
    """
    if metadata_list and len(metadata_list) != len(keys):
        raise XQException(message=f"metadata_list length ({len(metadata_list)}) must match keys length ({len(keys)})")

    entries = []
    for i, key in enumerate(keys):
        entry = {
            "type": type,
            "meta": metadata_list[i] if metadata_list else {},
            "key": key.decode("utf-8") if isinstance(key, bytes) else key,
            "recipients": recipients,
            "expires": expires_period,
            "timeUnit": time_unit
        }
        entries.append(entry)

    payload = {"entries": entries}

    status_code, res = api.api_post("packet/batch", json=payload, subdomain=API_SUBDOMAIN)

    if status_code == 200:
        return res
    else:
        print("status_code ", status_code)
        print(res)
        raise XQException(message=f"Batch packet creation failed: {res}")
