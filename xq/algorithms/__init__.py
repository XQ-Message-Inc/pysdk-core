from enum import Enum
from xq.algorithms.encryption import Encryption
from xq.algorithms.otp_encryption import OTPEncryption
from xq.algorithms.aes_encryption import AESEncryption


Algorithms = {"OTP": OTPEncryption, "AES": AESEncryption}
