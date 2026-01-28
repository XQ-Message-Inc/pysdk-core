from xq.api.subscription import API_SUBDOMAIN
from xq.algorithms.aes_encryption import AESEncryption
from xq.exceptions import XQException
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import base64
import json

def authorize_user(
    api,
    email: str
):
    """request pre-auth token for a given email address an email with a pin.
    https://xqmsg.com/docs/delta/#tag/authentication-management/post/v3/login/link

    :param api: XQAPI instance
    :type api: XQAPI
    :param user_email: email address of user requesting access token
    :type user_email: str
    """
    return api.send_login_link(email=email)


def authorize_alias(api, email: str):
    """request an access token for the given user information


    :param api: XQAPI instance
    :type api: XQAPI
    :param user_email: email address of user requesting access token
    :type user_email: str
    :return: return if login successful
    :rtype: boolean
    """

    return api.login_alias(email=email)



def load_file_content(file_path: str) -> str:
    """Load content from a file"""
    try:
        with open(file_path, 'r') as f:
            return f.read().strip()
    except FileNotFoundError:
        raise XQException(f"File not found: {file_path}")
    except Exception as e:
        raise XQException(f"Failed to read file {file_path}: {str(e)}")
     
def _rsa_decrypt_with_crypto(private_key_text: str, ciphertext: bytes) -> bytes:
    """
    Decrypt RSA ciphertext using a private key given as base64 DER or PEM text.
    Matches the C code's EVP_PKEY_decrypt (PKCS#1 v1.5).
    """
    t = private_key_text.strip()

    # If it looks like PEM, import directly
    if "BEGIN" in t:
        key = RSA.import_key(t.encode("utf-8"))
    else:
        # Otherwise assume base64-encoded DER (like C path)
        der = base64.b64decode(t)
        key = RSA.import_key(der)

    #from Crypto.Cipher import PKCS1_OAEP
    cipher = PKCS1_v1_5.new(key)
    # Second arg is a sentinel returned on failure; we choose None then check for it
    decrypted = cipher.decrypt(ciphertext, None)
    if decrypted is None:
        raise XQException("RSA decryption failed")
    return decrypted

def _normalize_transport_key(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        raise XQException("No transport key has been provided.")
    return raw

def create_certificate(api, tag: str, geofence: list[str], enabled: bool):
    """Create a certificate
    https://xqmsg.com/docs/delta/#tag/certificate-management/post/v3/certificate

    :param api: XQ API client instance
    :type api: XQAPI
    :param tag: The identifying tag of the new certificate.
    :type tag: str
    :param geofence: List of IPs or locations to require for this certificate.
    :type geofence: list[str]
    :param enabled: Specifies if this certificate is enabled or disabled.
    :type enabled: boolean
    :return: certificate created
    :rtype: dict with keys  transportKey, clientKey, clientCert, id
    :raises XQException: If the certificate cannot be created

    """
    payload = {
        "tag": tag,
        "geofence": geofence,
        "enabled": enabled
    }

    status_code, res = api.api_post(f"certificate", json=payload, subdomain=API_SUBDOMAIN)
    if status_code == 200:
        return res;
    else:
        raise XQException(message=f"Failed create certificate: {res}")

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
    
def login_certificate(api,
                      cert_id: int,
                      cert_data: str,
                      transport_key: str,
                      private_key: str,
                      device_name: str = "Demo",
                      firstName: str = "Local",
                      lastName: str = "Host"):
    """Login with a certificate .
    https://xqmsg.com/docs/delta/#tag/authentication-management/post/v3/login/cert

    :param api: XQ API client instance
    :type api: XQAPI
    :param cert_id: Certificate identifier issued for the device/tenant
    :type cert_id: int
    :param cert_data: client certificate (client.crt)
    :type cert_data: str
    :param transport_key:  Transport key used to encrypt the request payload (transport.key)
    :type transport_key: str
    :param private_key: Private key (client.key) used to decrypt the returned token
    :type private_key: str
    :param device_name:  Name of device
    :type device_name: str
    :param firstName:  First Name
    :type firstName: str
    :param lastName:  Last Name
    :type lastName: str
    :return: Access token for subsequent authenticated requests
    :rtype: str
    :raises XQException: If  the server time cannot be fetched, encryption/decryption fails, \
or the authorization request is rejected
    """
    ...

    status_code, time_response = api.api_get(
        f"time",
        subdomain=API_SUBDOMAIN,
    )
    if status_code != 200:
        raise XQException("Failed to get server time")

    ts = int(time_response)

    payload = {
        "crt": cert_data,
        "device": device_name,
        "firstName": firstName,
        "lastName": lastName,
        "ts": ts,
    }

    payload_json = json.dumps(payload)
    transport_key_wire = _normalize_transport_key(transport_key)
    AES_With_Transport = AESEncryption(transport_key_wire.encode("utf-8"))
    enc_bytes = AES_With_Transport.encrypt(payload_json.encode("utf-8"))
    enc_b64 = base64.b64encode(enc_bytes).decode("utf-8")

    api.headers["X-Certificate-ID"] = str(cert_id)
    status_code, response_content = api.api_post(
        f"login/cert",
        data=enc_b64,
        subdomain=API_SUBDOMAIN,
    )
    del api.headers["X-Certificate-ID"]
    del api.headers["X-Team-ID"]
    if status_code != 200:
        raise XQException(message=f"Authorization request failed with status {status_code}: {response_content}")
    else:
        try:
            resp_raw = base64.b64decode(response_content)
        except Exception as e:
            raise XQException(message=f"Failed to base64-decode response: {e}")

        try:
            dec_bytes = AES_With_Transport.decrypt(resp_raw)
        except Exception as e:
            raise XQException(message=f"Failed to AES-decrypt response: {e}")

        try:
            dec_json = json.loads(dec_bytes)
        except Exception as e:
            raise XQException(message=f"Failed to parse decrypted JSON: {e}")

        encrypted_token_b64 = dec_json.get("access_token")
        if not encrypted_token_b64:
            raise XQException(message="Failed to read access token")

        encrypted_token = base64.b64decode(encrypted_token_b64)

        ask_b64 = dec_json.get("ask")

        ask = base64.b64decode(ask_b64)

        try:
            decryptedAskBytes = _rsa_decrypt_with_crypto(private_key, ask)
        except Exception as e:
            raise XQException(message=f"Failed to RSA-decrypt ask: {e}")

        try:
            decryptedAsk = decryptedAskBytes.decode("utf-8")
            AES_With_Ask_Key = AESEncryption(decryptedAsk.encode("utf-8"))
            tokenString = AES_With_Ask_Key.decrypt(encrypted_token)
        except Exception as e:
            raise XQException(message=f"Failed to RSA-decrypt access token: {e}")

        token = json.loads(tokenString)

        access_token = token["access_token"]

        api.headers.update({"authorization": f"Bearer {access_token}"})

        return access_token

