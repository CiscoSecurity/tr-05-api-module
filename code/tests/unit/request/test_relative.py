from mock import MagicMock

from api.threatresponse.request.relative import RelativeRequest


def test_that_relative_request_invokes_inner_request():
    inner_request = MagicMock()

    request = RelativeRequest(inner_request, 'http://one.com')
    request.post('/two')

    inner_request.perform.assert_called_once()


def test_that_relative_request_builds_correct_parameters():
    inner_request = MagicMock()

    request = RelativeRequest(inner_request, 'http://one.com')
    request.post('/two', json={'some': 'data'})

    inner_request.perform.assert_called_once_with(
        'POST', 'http://one.com/two', json={'some': 'data'}
    )


def test_that_relative_request_returns_correct_response():
    inner_request = MagicMock()
    inner_request.perform.return_value = 'duck'

    request = RelativeRequest(inner_request, 'http://one.com')
    response = request.post('/two')

    assert response == 'duck'
