"""Generate AWS federated signin URL."""
import json
import urllib

import requests


def generate_signin_url(credentials,
                        destination='https://console.aws.amazon.com/',
                        issuer='https://example.com',
                        session_duration=None):
    """
    Return URL for federated console access.

    credentials: Dictionary defining AccessKeyId, SecretAccessKey, and
        SessionToken for the principal to sign in.
    destination: URL string to the desired AWS console page.
    issuer: URL string for your internal sign-in page.
    session_duration: Time in seconds for the duration of the console session.

    AWS documentation:
    https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_enable-console-custom-url.html
    """
    session = json.dumps({
        'sessionId': credentials['AccessKeyId'],
        'sessionKey': credentials['SecretAccessKey'],
        'sessionToken': credentials['SessionToken']
        })
    session_duration_param = '&SessionDuration{}'.format(session_duration) \
        if session_duration is not None else ''
    request_url = 'https://signin.aws.amazon.com/federation' \
        '?Action=getSigninToken' \
        '{session_duration_param}' \
        '&Session={session}'.format(
            session=urllib.parse.quote_plus(session),
            session_duration_param=session_duration_param)
    resp = requests.get(request_url)

    return 'https://signin.aws.amazon.com/federation' \
        '?Action=login' \
        '&Issuer={issuer}' \
        '&Destination={destination}' \
        '&SigninToken={signin_token}'.format(
            issuer=urllib.parse.quote_plus(issuer),
            destination=urllib.parse.quote_plus(destination),
            signin_token=json.loads(resp.text)['SigninToken'])
