from mock import patch

from threatresponse.request.relative import RelativeRequest


@patch('threatresponse.request.base.Request')
def test_that_relative_request_builds_correct_parameters(mock):
    request = RelativeRequest(mock, 'http://one.com')
    request.post('/two', json={'some': 'data'})

    mock.perform.assert_called_once_with('POST', 'http://one.com/two', json={'some': 'data'})


@patch('threatresponse.request.base.Request')
def test_that_relative_request_returns_correct_response(mock):
    mock.perform.return_value = 'duck'

    request = RelativeRequest(mock, 'http://one.com')
    response = request.post('/two')

    assert response == 'duck'
