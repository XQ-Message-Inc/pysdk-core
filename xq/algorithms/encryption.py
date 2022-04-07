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
        return self.expandedKey if hasattr(self, "expandedKey") else self.originalKey

    def expandKey(self, key, extendTo=2048):
        # replicated from jssdk-core

        key = re.sub("/\n$/", "", key)
        if len(key) >= extendTo:
            return key

        expandedKey = key
        while len(expandedKey) < extendTo:
            expandedKey += self.shuffle(key)

        return expandedKey

    def shuffle(self, string: str):
        # replicated from jssdk-core

        string_list = list(string)
        for i in range(len(string_list) - 1, -1, -1):
            j = math.floor(random.uniform(0, 1) * (i + 1))
            tmp = string_list[i]
            string_list[i] = string_list[j]
            string_list[j] = tmp

        return "".join(string_list)
