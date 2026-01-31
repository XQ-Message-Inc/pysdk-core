from xq.api.subscription import API_SUBDOMAIN
from xq.api.manage import announce_device
from xq.algorithms.aes_encryption import AESEncryption
from xq.exceptions import XQException
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from xq.config import API_KEY
import base64
import json
import os

def authorize_user(
    api,
    user_email: str,
    firstName: str = "",
    lastName: str = "",
    newsletter=False,
    notifications=0,
):
    """request pre-auth token for a given email address, this token will need to be exchanged for an access token
    https://xq.stoplight.io/docs/xqmsg/b3A6NDA5MDAxNDE-request-access-for-a-user

    :param api: XQAPI instance
    :type api: XQAPI
    :param user_email: email address of user requesting access token
    :type user_email: str
    :param firstName: first name of user, defaults to ""
    :type firstName: str, optional
    :param lastName: last name of user, defaults to ""
    :type lastName: str, optional
    :param newsletter: subscribe to newsletter, defaults to False
    :type newsletter: bool, optional
    :param notifications: notification level: 0 = No Notifications, 1 = Receive Usage Reports, 2 = Receive Tutorials, 3 = Receive Both, defaults to 0
    :type notifications: int, optional
    :return: pre-auth token, which can be exchanged for an access token
    :rtype: str
    """
    payload = {
        "user": user_email,
        "newsletter": newsletter,
        "notifications": notifications,
        **({} if not firstName else {"firstName": firstName}),
        **({} if not lastName else {"lastName": lastName}),
    }
    
    status_code, auth_token = api.api_post(
        "authorize",
        json=payload,
        subdomain=API_SUBDOMAIN,
    )

    # update auth header to use new bearer token
    api.headers.update({"authorization": f"Bearer {auth_token}"})

    if status_code == 200:
        api.set_api_auth_token(auth_token)
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
        api.set_api_auth_token(auth_token)
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
        api.set_api_auth_token(data.get('access_token'))

        # Announce the device to register it in the dashboard.
        status_code= announce_device(api, afirst=device)

        return data.get('access_token')
    else:
        return False
    
def exchange_for_subscription_token(api):
    """Exchange a dashboard token for a subscription token
    
    :param api: XQAPI instance
    :type api: XQAPI
    :param dashboard_token: dashboard token to exchange
    :type dashboard_token: str
    :return: subscription token
    :rtype: str
    """
    original_auth = api.headers.get("authorization")
    
    try:
        # Set the bearer token for this request
        api.headers.update({
            "authorization": f"Bearer {original_auth}",
            "api-key": API_KEY
        })
        
        status_code, subscription_token = api.api_get(
            "exchange",
            subdomain=API_SUBDOMAIN,
            params={"request": "dashboard"}
        )
        
        if status_code == 200:
            api.set_api_auth_token(subscription_token)
            api.headers.update({"authorization": f"Bearer {subscription_token}"})
            return subscription_token
        else:
            raise XQException(f"Failed to exchange token: {status_code}")

    finally:
        # Restore the original authorization header
        if original_auth:
            api.headers["authorization"] = original_auth
        # Restore Content-Type to default
        api.headers["Content-Type"] = "application/json"

def _load_or_use_content(value: str) -> str:
    """Load content from file path or use the value directly
    
    :param value: Either a file path or the actual content
    :type value: str
    :return: The content
    :rtype: str
    """
    if not value:
        raise XQException("Value must be provided.")
    
    if os.path.exists(value):
        try:
            with open(value, 'r') as f:
                return f.read().strip()
        except Exception as e:
            raise XQException(f"Failed to read file {value}: {str(e)}")
    
    return value.strip()
     
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

def authorize_device_cert(api, cert_id: int, cert_file_path: str, transport_key_file_path: str, private_key_file_path: str, device_name: str = "Device", announce: bool = True):
    """Authorize a device using an XQ certificate and transport key, returning an access token.

    :param api: XQ API client instance
    :type api: XQAPI
    :param cert_id: Certificate identifier issued for the device/tenant
    :type cert_id: int
    :param cert_file_path: Path to the client certificate file (client.crt) OR the certificate content directly
    :type cert_file_path: str
    :param transport_key_file_path: Path to the transport key file (transport.key) OR the transport key content directly
    :type transport_key_file_path: str
    :param private_key_file_path: Path to the device private key file (client.key) OR the private key content directly
    :type private_key_file_path: str
    :param device_name: Human-readable device name (max 48 characters), defaults to Device
    :type device_name: str
    :param announce: If True, announce the device to the dashboard after authorization, defaults to True
    :type announce: bool, optional
    :return: Access token for subsequent authenticated requests
    :rtype: str
    :raises XQException: If files are missing/empty, the server time cannot be fetched, encryption/decryption fails, \
or the authorization request is rejected
    """
    if not device_name or len(device_name) > 48:
        raise XQException(message="Device name must be provided and cannot exceed 48 characters.")
    try:
        cert_data = _load_or_use_content(cert_file_path)
        if not cert_data:
            raise XQException(message="Certificate is empty.")
        
        transport_key = _load_or_use_content(transport_key_file_path)
        if not transport_key:
            raise XQException(message="Transport key is empty.")
        
        private_key_content = _load_or_use_content(private_key_file_path)
        if not private_key_content:
            raise XQException(message="Private key is empty.")

        try:
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
                "ver": 3,
                "ts": ts,
            }
            
            payload_json = json.dumps(payload)
            transport_key_wire = _normalize_transport_key(transport_key)
            AES = AESEncryption(transport_key_wire.encode("utf-8"))
            enc_bytes = AES.encrypt(payload_json.encode("utf-8"))
            enc_b64 = base64.b64encode(enc_bytes).decode("utf-8")

            status_code, response_content = api.api_post(
                f"authorize/certificate/{cert_id}",
                data=enc_b64,
                subdomain=API_SUBDOMAIN,
            )

            if status_code != 200:
                raise XQException(message=f"Authorization request failed with status {status_code}: {response_content}")
            else:
                try:
                    resp_raw = base64.b64decode(response_content)
                except Exception as e:
                    raise XQException(message=f"Failed to base64-decode response: {e}")

                try:
                    dec_bytes = AES.decrypt(resp_raw)
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

                try:
                    token_bytes = _rsa_decrypt_with_crypto(private_key_content, encrypted_token)
                except Exception as e:
                    raise XQException(message=f"Failed to RSA-decrypt access token: {e}")

                access_token = token_bytes.decode("utf-8")
                api.headers.update({"authorization": f"Bearer {access_token}"})
                api.set_api_auth_token(access_token)
                api.set_dashboard_auth_token(access_token)

                if announce:
                    status_code = announce_device(api, afirst=device_name)
                
                return access_token
        except ValueError:
            raise XQException(message="Failed to get time from API.")
    except XQException:
        raise