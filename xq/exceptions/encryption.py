from xq.exceptions import XQException


class SDKEncryptionException(XQException): # pragma: no cover
    def __init__(self, message="There was an issue with encryption"):
        """Exception raised for SDK initalization errors.

        :param message: error message to send to user, defaults to "There was an issue with encryption"
        :type message: str, optional
        """
        self.message = message
        super().__init__(self.message)
