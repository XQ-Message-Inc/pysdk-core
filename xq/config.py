import os
from dotenv import load_dotenv

# Declare global variables with default values
API_BASE_URI = None
API_KEY = None
DASHBOARD_API_KEY = None
XQ_LOCATOR_KEY = None

def configure_env(dotenv_path=None):
    global API_BASE_URI, API_KEY, DASHBOARD_API_KEY, XQ_LOCATOR_KEY

    if dotenv_path:
        load_dotenv(dotenv_path)
    else:
        load_dotenv(os.path.join(os.getcwd(), '.env'))
    
    API_BASE_URI = os.environ.get("XQ_BASE_URI", "xqmsg.net/v2/")
    API_KEY = os.environ.get("XQ_API_KEY")
    DASHBOARD_API_KEY = os.environ.get("XQ_DASHBOARD_API_KEY")
    XQ_LOCATOR_KEY = os.environ.get("XQ_LOCATOR_KEY")

configure_env()
