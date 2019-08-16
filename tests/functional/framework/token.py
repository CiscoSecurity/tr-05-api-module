from ctrlibrary.core import client, settings
from tests.functional.framework.endpoints import TOKEN_URL


def request_token(ctr_client_id, ctr_client_password):
    """Request authentication token from Threat Response server"""
    data = {'grant_type': 'client_credentials'}
    headers = {
        'content-type': 'application/x-www-form-urlencoded',
        'accept': 'application/json'
    }
    response = client.post(
        url=''.join((settings.server.ctr_hostname, TOKEN_URL)),
        data=data,
        headers=headers,
        auth=(ctr_client_id, ctr_client_password)
    )

    return response.json()['access_token']
