from xq.exceptions import XQException
from xq.api.subscription import API_SUBDOMAIN

def create_team(api, name: str, domain: str = None, ownerEmail: str = None, permit: str = None, permitTeam: str = None):
    """create a team
    https://xqmsg.com/docs/delta/#tag/team-management/post/v3/team

    :param api: XQAPI instance
    :type api: XQAPI
    :param name: name of the team
    :type name: str
    :param domain: domain of the team
    :type domain: str. optional
    :param ownerEmail:  email  of the team's owner
    :type ownerEmail: str. optional
    :param permit: permit of the team
    :type domain: str. optional
    :param permitTeam: permitTeam of the team
    :type domain: str. optional
    :raises XQException: error creating team
    :return: id of created team
    :rtype: int
    """
    payload = {"name": name}
    if domain:
        payload["domain"] = domain
    if ownerEmail:
        payload["ownerEmail"] = ownerEmail
    if permit:
        payload["permit"] = permit
    if permitTeam:
        payload["permitTeam"] = permitTeam

    status_code, res = api.api_post("team", json=payload, subdomain=API_SUBDOMAIN)

    if status_code == 200:
        return res["id"]
    else:
        raise XQException(message=f"Error with status code {status_code} creating team: {res}")


def get_teams(api):
    """get the registered teams
    https://xqmsg.com/docs/delta/#tag/team-management/get/v3/teams/registered

    :param api: XQAPI instance
    :type api: XQAPI
    :return: teams(s)
    :rtype: array of team dict
    """

    status_code, res = api.api_get("teams/registered", subdomain=API_SUBDOMAIN)

    if status_code == 200:
        return res
    else:
        raise XQException(message=f"Error with status code {status_code} getting teams: {res}")

def switch(api, teamId: str):
    """exchange pre-auth token for an access token, and update headers accordingly
    https://xqmsg.com/docs/delta/#tag/team-management/get/v3/teams/switch

    :param api: XQAPI instance
    :type api: XQAPI
    :param teamId: teamId
    :type teamId: int
    :raises XQException: key exchange failure
    :return: access_token
    :rtype: str
    """
    status_code, res = api.api_get(
        "teams/switch", params={"id": teamId}, subdomain=API_SUBDOMAIN
    )

    if status_code == 200:
        access_token = res["access_token"]
        api.headers.update({"authorization": f"Bearer {access_token}"})
        api.headers["X-Team-ID"] = str(str(teamId))
        return res["access_token"]
    else:
        raise XQException(message=f"Key Exchange creation failed: {res}")


def delete_team(api, team_id: int):
    """delete a team by id
    https://xqmsg.com/docs/delta/#tag/team-management/delete/v3/team

    :param api: XQAPI instance
    :type api: XQAPI
    :param team_id: id number of usergroup
    :type team_id: int
    :raises XQException: error deleting usergroup
    :return: success
    :rtype: boolean
    """
    status_code, res = api.api_delete(
        f"team?team={team_id}", subdomain=API_SUBDOMAIN
    )

    if status_code == 204:
        return True
    else:
        raise XQException(message=f"Error deleting Team: {res}")
