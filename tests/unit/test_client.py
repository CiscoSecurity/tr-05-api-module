import pytest
from mock import patch, MagicMock
from requests import HTTPError

from threatresponse.api import (
    InspectAPI,
    EnrichAPI,
    ResponseAPI,
    IntelAPI,
)
from threatresponse.client import ThreatResponse
from threatresponse.exceptions import RegionError


@patch('requests.Session.request')
def test_types_of_inner_apis(_):
    client = ThreatResponse('CLIENT_ID', 'CLIENT_PASSWORD')

    assert isinstance(client.inspect, InspectAPI)
    assert isinstance(client.enrich, EnrichAPI)
    assert isinstance(client.response, ResponseAPI)
    assert isinstance(client.private_intel, IntelAPI)
    assert isinstance(client.global_intel, IntelAPI)


@patch('requests.Session.request')
def test_different_regions(_):
    def TR(region):
        return ThreatResponse('CLIENT_ID', 'CLIENT_PASSWORD', region=region)

    for region in [None, '', 'us', 'eu', 'apjc']:
        TR(region)

    for region in ['foo', 'bar']:
        with pytest.raises(RegionError):
            TR(region)


@patch('requests.Session.request')
def test_that_client_with_valid_credentials_succeeds(inner_session_request):
    inner_session_request.return_value = auth_response(200)

    logger = MagicMock()

    ThreatResponse(
        client_id='CLIENT_ID',
        client_password='CLIENT_PASSWORD',
        logger=logger,
    )

    # Verify that only a single request has been made to an external API.
    # Don't check the actual arguments since we're not interested in any
    # auth-specific details here.
    inner_session_request.assert_called_once()

    logger.info.assert_called_once_with(
        'POST https://visibility.amp.cisco.com/iroh/oauth2/token 200 OK'
    )


@patch('requests.Session.request')
def test_that_client_with_invalid_credentials_fails(inner_session_request):
    inner_session_request.return_value = auth_response(401)

    logger = MagicMock()

    with pytest.raises(HTTPError):
        ThreatResponse(
            client_id='CLIENT_ID',
            client_password='CLIENT_PASSWORD',
            logger=logger,
        )

    # Verify that only a single request has been made to an external API.
    # Don't check the actual arguments since we're not interested in any
    # auth-specific details here.
    inner_session_request.assert_called_once()

    logger.error.assert_called_once_with(
        'POST https://visibility.amp.cisco.com/iroh/oauth2/token 401 '
        'Unauthorized'
    )


def auth_response(status_code):
    mocked = MagicMock()
    mocked.status_code = status_code
    mocked.ok = 100 <= status_code < 400

    if mocked.ok:
        mocked.json.return_value = {'access_token': 'ACCESS_TOKEN'}

    else:
        error = HTTPError('Some error message here.', response=mocked)

        mocked.text = '{"error": "ERROR"}'
        mocked.raise_for_status.side_effect = error

    return mocked
