import os
from dotenv import load_dotenv

# Declare global variables with default values
API_BASE_URI = None
API_KEY = None
XQ_LOCATOR_KEY = None
XQ_URI_SCHEME = None

def configure_env(dotenv_path=None):
    global API_BASE_URI, API_KEY, XQ_LOCATOR_KEY,XQ_URI_SCHEME

    if dotenv_path:
        load_dotenv(dotenv_path)
    else:
        load_dotenv(os.path.join(os.getcwd(), '.env'))
    
    API_BASE_URI = os.environ.get("XQ_BASE_URI", "xqmsg.net/v2/")
    XQ_URI_SCHEME = os.environ.get("XQ_URI_SCHEME", "https")
    API_KEY = os.environ.get("XQ_API_KEY")
    XQ_LOCATOR_KEY = os.environ.get("XQ_LOCATOR_KEY")

configure_env()
