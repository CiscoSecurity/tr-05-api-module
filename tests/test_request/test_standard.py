from mock import patch

from threatresponse.request.standard import StandardRequest


@patch('requests.Session.request')
def test_that_standard_request_simply_wraps_session(inner_session_request):
    request = StandardRequest()
    request.post(
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
