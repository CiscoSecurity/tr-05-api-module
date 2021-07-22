from mock import patch

from api.threatresponse.request.response import Response
from api.threatresponse.request.standard import StandardRequest


@patch('requests.Session.request')
def test_that_standard_request_wraps_session_response(inner_session_request):
    request = StandardRequest()
    response = request.post(
        '/foo/bar',
        json={'spam': 'eggs'},
        headers={'Threat': 'Response'},
    )

    inner_session_request.assert_called_once_with(
        'POST',
        '/foo/bar',
        json={'spam': 'eggs'},
        headers={'Threat': 'Response'},
    )
    assert isinstance(response, Response)
