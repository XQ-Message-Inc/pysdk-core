from xq.exceptions import XQException


def create_packet(api, recipients, expires_hours=24, key: bytes = None):

    payload = {
        "recipients": recipients,
        "expires": expires_hours,
        "key": key.decode("utf-8"),
    }
    status_code, res = api.api_post("packet", data=payload)

    if status_code == 200:
        return res
    else:
        raise XQException(message=f"Packet creation failed: {res}")


def store_packet(api, encrypted_key_packet, expires_hours=24):
    payload = {
        "expires": expires_hours,
        "key": encrypted_key_packet,
    }
    status_code, res = api.api_post("packet", data=payload)

    print(status_code, res)

    if status_code == 200:
        return res
    else:
        raise XQException(message=f"Packet storage failed: {res}")
