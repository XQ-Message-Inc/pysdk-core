import os
from os.path import join, dirname
from dotenv import load_dotenv

def configure_env(dotenv_path=None):
    if dotenv_path:
        load_dotenv(dotenv_path)
    else:
        load_dotenv()

configure_env()

# set global XQ config variables
API_BASE_URI = "xqmsg.net/v2/"
API_KEY = os.environ.get("XQ_API_KEY", None)
DASHBOARD_API_KEY = os.environ.get("XQ_DASHBOARD_API_KEY", None)
XQ_LOCATOR_KEY= os.environ.get("XQ_LOCATOR_KEY", None)
