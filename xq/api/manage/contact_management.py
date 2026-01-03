from xq.exceptions import XQException
from xq.api.manage import API_SUBDOMAIN


ROLES = {
    1: "Administrator",
    2: "User",
    3: "Vendor",
    4: "Customer",
    5: "SystemAdmin",
    6: "AuthorizedDevice",
    7: "Guest",
    8: "Manager",
    9: "Recipient",
    10: "AliasUser"
}

def add_team_member(
    api,
    firstName: str,
    lastName: str,
    email: str,
    title: str,
    role: int,
    phone: str = None,
    requiresAuth: bool = None,
    host: str = None,
    template: str = None,
    subject: str = None
):
    f"""add  team member 
    https://xqmsg.com/docs/delta/#tag/team-management/post/v3/team/invite

    :param api: XQAPI instance
    :type api: XQAPI
    :param firstName: first name of team member
    :type firstName: str
    :param lastName: last name of team member
    :type lastName: str
    :param email: email address of team member
    :type email: str
    :param title: business title of team member
    :type title: str
    :param role: user role to assign team member, {str(ROLES)}
    :type role: int
    :param phone: phone of team member
    :type phone: str
    :param host: the host URL from where this request was triggered
    :type host: str
    :param template: the name of template team members  login link configuration template.
    :type template: str
    :param subject: An optional subject line for communications related to the invite of the team member
    :type subject: str
    :param requiresAuth: does the team member require auth 
    :type requiresAuth: str
    :rtype dict with keys  id and code
    """
    if role not in ROLES.values():
        raise XQException(
            f'Provided Role "{role}" is not valid.  Available options are: {ROLES}'
        )

    payload = {
        "email": email,
        "role": role,
    }
    if firstName:
        payload["firstName"] = firstName
    if lastName:
        payload["lastName"] = lastName
    if title:
        payload["title"] = title
    if phone:
        payload["phone"] = phone
    if host:
        payload["host"] = host
    if template:
        payload["template"] = template
    if subject:
        payload["subject"] = subject
    if requiresAuth:
        payload["requiresAuth"] = requiresAuth

    status_code, res = api.api_post("team/invite", json=payload, subdomain=API_SUBDOMAIN)

    if status_code == 200:
        return res
    else:
        raise XQException(message=f"Error adding team member  user: {res}")

def delete_team_member(api, id: int):
    f"""delete a team member 
    https://xqmsg.com/docs/delta/#tag/team-management/delete/v3/team/member/{id}

    :param api: XQAPI instance
    :type api: XQAPI
    :param id: id of team member to be deleted 
    :type id: int
    :return: success
    :rtype: boolean
    """
    status_code, res = api.api_delete(
        f"team/member/{id}", subdomain=API_SUBDOMAIN
    )

    if status_code == 204:
        return True
    else:
        raise XQException(message=f"Error deleting team member {res}")
