import os
from os.path import join, dirname
from dotenv import load_dotenv

# load dotenv file into ENV
dotenv_path = join(dirname(__file__), "..", ".env")
d = load_dotenv(dotenv_path)

# set global XQ config variables
API_BASE_URI = "xqmsg.net/v2/"
# API_HEADERS = {"authorization": "Bearer xyz123", "Content-Type": "application/json"}
API_KEY = os.environ.get("XQ_API_KEY", None)
DASHBOARD_API_KEY = os.environ.get("XQ_DASHBOARD_API_KEY", None)
