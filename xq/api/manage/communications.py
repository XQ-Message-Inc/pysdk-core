from typing import Optional

from xq.exceptions import XQException
from xq.api.manage import API_SUBDOMAIN
from xq.config import DASHBOARD_API_KEY
import urllib.parse

def get_communication_by_locator_token(api, locator_token: str):
    """Get a single communication by its locator token.
    https://xq.stoplight.io/docs/xqmsg/005edb8a9ec2b-get-communication-by-its-locator-token

    :param api: XQAPI instance
    :type api: XQAPI
    :raises XQException: invalid access token
    :return: validated
    :rtype: boolean
    """
    api.headers.update(
        {"api-key": DASHBOARD_API_KEY}
    )  # dashboard api token needs to be set in the header

    status_code, res = api.api_get(
        f"communication/{urllib.parse.quote_plus(locator_token)}", subdomain=API_SUBDOMAIN
    )

    if status_code == 200:
        return res
    else:
        raise XQException(message=f"Communication retrieval failed: {res}")
    
def add_labels_to_locator_token(api, locator_token: str, labels: list):
    """Add labels to a communication by its locator token.

    :param api: XQAPI instance
    :type api: XQAPI
    :raises XQException: invalid access token
    :return: validated
    :rtype: boolean
    """
    api.headers.update(
        {"api-key": DASHBOARD_API_KEY}
    ) 

    payload = {
        "labels": labels
    }

    status_code, res = api.api_patch(
        f"communication/{urllib.parse.quote_plus(locator_token)}/labels", json=payload, subdomain=API_SUBDOMAIN
    )

    if status_code == 200 or status_code == 204:
        return res
    else:
        raise XQException(message=f"Adding labels failed: {res}")


def list_communications(
    api,
    page: Optional[int] = None,
    limit: Optional[int] = None,
    from_time: Optional[int] = None,
    to_time: Optional[int] = None,
    tz: Optional[int] = None,
    recipients: Optional[str] = None,
    users: Optional[str] = None,
    search: Optional[str] = None,
    status: Optional[str] = None,
    comm_type: Optional[str] = None,
):
    """List all available communications of a workspace.
    https://xq.stoplight.io/docs/xqmsg/6bcf3698bb5b4-list-communications

    :param api: XQAPI instance
    :type api: XQAPI
    :param page: page number for pagination, defaults to None
    :type page: int, optional
    :param limit: page size, defaults to None
    :type limit: int, optional
    :param from_time: lower boundary time in milliseconds, defaults to None
    :type from_time: int, optional
    :param to_time: upper boundary time in milliseconds, defaults to None
    :type to_time: int, optional
    :param tz: timezone offset (e.g. -6 for CST), defaults to None
    :type tz: int, optional
    :param recipients: filter by recipient email (comma separated), defaults to None
    :type recipients: str, optional
    :param users: filter by sender email (comma separated), defaults to None
    :type users: str, optional
    :param search: generic search matching resource names, recipients, and owners, defaults to None
    :type search: str, optional
    :param status: comma separated status filter (0=Available, 1=Revoked, 2=Expired), defaults to None
    :type status: str, optional
    :param comm_type: key type filter (0=Unknown, 1=File, 2=Email, comma separated), defaults to None
    :type comm_type: str, optional
    :raises XQException: error listing communications
    :return: communications list with total count
    :rtype: dict
    """
    params = {}

    if page is not None:
        params["page"] = page
    if limit is not None:
        params["limit"] = limit
    if from_time is not None:
        params["from"] = from_time
    if to_time is not None:
        params["to"] = to_time
    if tz is not None:
        params["tz"] = tz
    if recipients is not None:
        params["recipients"] = recipients
    if users is not None:
        params["users"] = users
    if search is not None:
        params["search"] = search
    if status is not None:
        params["status"] = status
    if comm_type is not None:
        params["type"] = comm_type

    api.headers.update(
        {"api-key": DASHBOARD_API_KEY}
    )

    status_code, res = api.api_get(
        "communications", subdomain=API_SUBDOMAIN, params=params
    )

    if status_code == 200:
        return res
    else:
        raise XQException(message=f"Listing communications failed: {res}")