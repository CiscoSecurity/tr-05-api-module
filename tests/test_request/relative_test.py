from threatresponse.request.base import Request
from threatresponse.request.relative import RelativeRequest
from ..common import patch


@patch(Request)
def test_that_relative_request_invokes_inner_request(mock):
    request = RelativeRequest(mock, 'http://one.com')
    request.post('/two')

    mock.perform.assert_called_once()


@patch(Request)
def test_that_relative_request_builds_correct_parameters(mock):
    request = RelativeRequest(mock, 'http://one.com')
    request.post('/two', json={'some': 'data'})

    mock.perform.assert_called_once_with('POST', 'http://one.com/two', json={'some': 'data'})


@patch(Request)
def test_that_relative_request_returns_correct_response(mock):
    mock.perform.return_value = 'duck'

    request = RelativeRequest(mock, 'http://one.com')
    response = request.post('/two')

    assert response == 'duck'
