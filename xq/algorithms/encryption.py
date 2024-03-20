import re
import random
import math


class Encryption:
    """parent class for all encryption algorithms"""

    def __init__(self, key: str):
        """initialize shared algorithm functionality

        :param key: encryption key
        :type key: bytes
        """
        self.originalKey = key.encode() if isinstance(key, str) else key

    @property
    def key(self):
        """method property that returns the correct key value used for encryption

        :return: key used for encryption
        :rtype: bytes
        """
        return self.originalKey

    def shuffle(self, string: str = None):
        """psudo-randomize a provided string
        * replicated from jssdk-core

        :param string: provided string to randomize
        :type string: str
        :return: randomized string
        :rtype: str
        """
        string = string if string else self.key
        string_list = list(string)
        for i in range(len(string_list) - 1, -1, -1):
            j = math.floor(random.uniform(0, 1) * (i + 1))
            tmp = string_list[i]
            string_list[i] = string_list[j]
            string_list[j] = tmp

        try:
            # try string of bytes
            bytes_string = bytes(string_list).decode()
            assert len(bytes_string) == len(
                string
            ), "unexpected shuffle! new length does not match original"

            return bytes_string
        except:
            # just a regular string
            return "".join(string_list)
