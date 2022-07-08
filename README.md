# @xqmsg/pysdk-core
A Python Implementation of XQ Message SDK (V.2) which provides convenient access to the XQ Message API. [Full Package Documentation](https://xq-message-inc.github.io/pysdk-core/).

**Supports Python 3.8 | 3.9 | 3.10**


## What is XQ Message?

XQ Message is an encryption-as-a-service (EaaS) platform which gives you the tools to encrypt and route data to and from devices like mobile phones, IoT, and connected devices that are at the "edge" of the internet. The XQ platform is a lightweight and highly secure cybersecurity solution that enables self protecting data for perimeterless [zero trust](https://en.wikipedia.org/wiki/Zero_trust_security_model) data protection, even to devices and apps that have no ability to do so natively.

XQ is about the secure transfer of data in motion and throughout its lifecycle. XQ protects, controls, and tracks all the interactions with the data. XQ monitors what entities attempt access, where they are located and when the interaction occurs.


## installation

### production
```
pip install git+ssh://git@github.com/XQ-Message-Inc/python-sdk.git@main#egg=xq-sdk
```

### local/development
```
git clone git@github.com:XQ-Message-Inc/python-sdk.git
pip install -e .
```

#### API Keys

In order to utilize the XQ SDK and interact with XQ servers you will need both the **`General`** and **`Dashboard`** API keys. To generate these keys, follow these steps:

1. Go to your [XQ management portal](https://manage.xqmsg.com/applications).
2. Select or create an application.
3. Create a **`General`** key for the XQ framework API.
4. Create a **`Dashboard`** key for the XQ dashboard API.


## Basic Usage

#### Initializing the SDK

To initialize an XQ SDK instance in your Python application, provide the generated `XQ_API_KEY` (General) and/or `XQ_DASHBOARD_API_KEY` (Dashboard) API keys to the `XQ` class.

This can be done via:
- Input parameters (shown below)
- ENVIRONMENT VARS
- .env file

```python
import xq

xq = XQ(
  api_key="YOUR_XQ_API_KEY",
  dashboard_api_key="YOUR_DASHBOARD_API_KEY"
)
```

**_Note: You only need to generate one SDK instance for use across your application._**

#### Examples
There are detailed usage examples available in the [examples folder](https://github.com/XQ-Message-Inc/python-sdk/tree/main/examples) of this project.

**Roundtrip Encryption Examples:**
 - [BYOK w/ 2FA](examples/roundtrip_with_2fa.py)
 - [XQ Generated Entropy Key](examples/roundtrip_with_entropy_key.py)
 - [File Encryption](examples/roundtrip_otp_file.py)
 - [Magic Encrypt Text](examples/magic_encryption.py)
 - [Magic Encrypt File](examples/magic_encryption_file.py)
 - [Dashboard (Beta)](examples/dashboard.py)


## Help

#### Decoding Error
```'utf-8' codec can't decode byte 0xd2 in position 16: invalid continuation byte```
This is caused by an incorrect encoding being used with the provide byte string on `encryption`/`decryption`.  This is prevelant for zip files, like `.docx`.

To resolve, pass the correct encoding (zip typically uses `CP437`):
```
    cipherbytes = otp.encrypt(docxBytes, encoding="CP437")
    decrypted_bytes = otp.decrypt(ciphertext, encoding="CP437")
```


## Development

### Run Tests
```
pytest
```

#### Run Tests with Coverage HTML Reports
```
coverage run -m pytest
coverage html
```

### Build Documentation
```
sphinx-apidoc -f -o docs/ xq/
cd docs
make html
```
