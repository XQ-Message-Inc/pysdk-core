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
        key_string = key if isinstance(key, str) else key.decode()
        self.originalKey = key_string.encode()

    @property
    def key(self):
        """method property that returns the correct key value used for encryption

        :return: key used for encryption
        :rtype: bytes
        """
        return self.expandedKey if hasattr(self, "expandedKey") else self.originalKey

    def expandKey(self, key, extendTo=2048):
        """expands a key to a minimum defined length
        * replicated from jssdk-core

        :param key: encryption key
        :type key: bytes
        :param extendTo: length to expand key to, defaults to 2048
        :type extendTo: int, optional
        :return: expanded key
        :rtype: bytes
        """
        key = re.sub("/\n$/", "", key)
        if len(key) >= extendTo:
            return key

        expandedKey = key
        while len(expandedKey) < extendTo:
            expandedKey += self.shuffle(key)

        return expandedKey

    def shuffle(self, string: str):
        """psudo-randomize a provided string
        * replicated from jssdk-core

        :param string: provided string to randomize
        :type string: str
        :return: randomized string
        :rtype: str
        """
        string_list = list(string)
        for i in range(len(string_list) - 1, -1, -1):
            j = math.floor(random.uniform(0, 1) * (i + 1))
            tmp = string_list[i]
            string_list[i] = string_list[j]
            string_list[j] = tmp

        return "".join(string_list)
