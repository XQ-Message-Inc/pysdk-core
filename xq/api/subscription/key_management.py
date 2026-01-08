from xq.exceptions import XQException
from xq.api.subscription import API_SUBDOMAIN


def create_packet(
    api,
    recipients: list,
    expires_hours: int = 24,
    key: bytes = None,
    type: int = 3,
    subject: str = None,
):
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
        "meta": {"subject": subject},
        "type": type,
        "recipients": recipients,
        "expires": expires_hours,
        "key": key.decode("utf-8") if isinstance(key, bytes) else key,
    }
    status_code, res = api.api_post("packet", json=payload, subdomain=API_SUBDOMAIN)

    if status_code == 200:
        return res
    else:
        raise XQException(message=f"Packet creation failed: {res}")


def create_and_store_packet(
    api,
    recipients: list,
    expires_hours: int = 24,
    key: bytes = None,
    type: int|str = 'msg',
    subject: str = None,
    labels: list = None
):
    """creates an encrypted packet from a secret key
    https://xq.stoplight.io/docs/xqmsg/1f9bc1713a7cd-create-and-save-a-new-key-packet

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
        "meta": {"subject": subject,"title": subject, "labels": labels},
        "type": type,
        "recipients": recipients,
        "expires": expires_hours,
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
    expires_hours: int = 24,
    keys: list = None,
    type: int|str = 5,
    subject: str = None,
    meta: str = None
):
    """creates an encrypted packet from a secret key
    https://xq.stoplight.io/docs/xqmsg/1f9bc1713a7cd-create-and-save-a-new-key-packet

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
        "meta": {"subject": subject, "meta": meta},
        "type": type,
        "recipients": recipients,
        "expires": expires_hours,
        "keys": [k.decode("utf-8") if isinstance(k, bytes) else k for k in keys],
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
    expires: int = 1,
    unit: str = "days",
    type: str = "database"
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
    :param expires: expiration time (applies to all entries), defaults to 1
    :type expires: int, optional
    :param unit: time unit for expiration (applies to all entries), defaults to "days"
    :type unit: str, optional
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
            "expires": expires,
            "unit": unit
        }
        entries.append(entry)
    
    payload = {"entries": entries}
    
    status_code, res = api.api_post("packet/batch", json=payload, subdomain=API_SUBDOMAIN)

    if status_code == 200:
        return res
    else:
        raise XQException(message=f"Batch packet creation failed: {res}")
