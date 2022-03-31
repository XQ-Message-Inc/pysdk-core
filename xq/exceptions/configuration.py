from xq.exceptions import XQException


class SDKConfigurationException(XQException):
    def __init__(self, message="No API keys were provided"):
        """Exception raised for SDK initalization errors.

        :param message: error message to send to user, defaults to "No API keys were provided"
        :type message: str, optional
        """
        self.message = message
        super().__init__(self.message)
