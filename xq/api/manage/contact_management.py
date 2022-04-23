from xq.exceptions import XQException
from xq.api.manage import API_SUBDOMAIN

CONTACT_ROLES = {
    1: "Admin",
    2: "User",
    3: "Vendor",
    4: "Customer",
    5: "Super User",
    6: "Device",
}
NOTIFICATIONS = {
    0: "None",
    2: "Warnings and Alerts",
    3: "Alerts Only",
}  # [sic] docs have no '1'


def add_contact(
    api,
    firstName: str,
    lastName: str,
    email: str,
    title: str,
    role: int,
    notifications: int = 0,
    overflow: bool = False,
):
    f"""add external contact as an alias user
    https://xq.stoplight.io/docs/xqmsg/b3A6NDEyMDU5ODc-add-a-new-business-contact

    :param api: XQAPI instance
    :type api: XQAPI
    :param firstName: first name of contact
    :type firstName: str
    :param lastName: last name of contact
    :type lastName: str
    :param email: email address of contact
    :type email: str
    :param title: business title of contact
    :type title: str
    :param role: user role to assign contact, {str(CONTACT_ROLES)}
    :type role: int
    :param notifications: notification for contact, {str(NOTIFICATIONS)},defaults to 0
    :type notifications: int, optional
    :param overflow: _description_, defaults to False
    :type overflow: bool, optional
    """
    if role not in CONTACT_ROLES:
        raise XQException(
            f'Provided Role "{role}" is not valid.  Available options are: {CONTACT_ROLES}'
        )

    if notifications not in NOTIFICATIONS:
        raise XQException(
            f'Provided Notifications "{notifications}" is not valid.  Available options are: {NOTIFICATIONS}'
        )

    payload = {
        "firstName": firstName,
        "lastName": lastName,
        "email": email,
        "title": title,
        "role": role,
        "notifications": notifications,
        "overflow": overflow,
    }

    status_code, res = api.api_post("contact", json=payload, subdomain=API_SUBDOMAIN)

    if status_code == 200:
        return res
    else:
        raise XQException(message=f"Error registering Dashboard user: {res}")
