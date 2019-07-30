from mock import patch, MagicMock

from threatresponse.api import (
    InspectAPI,
    EnrichAPI,
)
from threatresponse.client import ThreatResponse


@patch('requests.Session.request')
def test_composite_structure(inner_session_request):
    auth_response = MagicMock()
    auth_response.status_code = 200
    auth_response.ok = True
    auth_response.json = lambda: {'access_token': 'ACCESS_TOKEN'}

    inner_session_request.return_value = auth_response

    logger = MagicMock()

    client = ThreatResponse(
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

    assert isinstance(client.inspect, InspectAPI)
    assert isinstance(client.enrich, EnrichAPI)
