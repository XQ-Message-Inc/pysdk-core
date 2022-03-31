class XQException(Exception):
    """Generic XQException wrapper."""

    def __init__(self, message="An Unknown Error Occured") -> None:
        self.message = message
        super().__init__(message)
