from typing import Union


class Encryption:
    """parent class for all encryption algorithms"""

    def __init__(self, key: bytes):
        """initialize shared algorithm functionality

        :param key: encryption key
        :type key: bytes
        """
        self.key = key
