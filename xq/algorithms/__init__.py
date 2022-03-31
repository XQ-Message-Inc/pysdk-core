from enum import Enum
from xq.algorithms.encryption import Encryption
from xq.algorithms.otpEncryption import OTPEncryption
from xq.algorithms.aesEncryption import AESEncryption


Algorithms = {"OTP": OTPEncryption, "AES": AESEncryption}
