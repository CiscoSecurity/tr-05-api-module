from mock import patch

from threatresponse.request.standard import StandardRequest


@patch('requests.Session.request')
def test_perform(mock):
    request = StandardRequest()
    request.perform(
        'POST', '/foo/bar',
        json={'spam': 'eggs'},
        headers={'Threat': 'Response'},
    )

    mock.assert_called_once_with(
        'POST', '/foo/bar',
        json={'spam': 'eggs'},
        headers={'Threat': 'Response'},
    )
