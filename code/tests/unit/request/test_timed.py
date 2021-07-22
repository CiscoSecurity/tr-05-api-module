from mock import MagicMock

from api.threatresponse.request.timed import TimedRequest


def test_that_timed_request_sets_default_timeout_if_not_specified():
    inner_request = MagicMock()
    default_timeout = 3.14

    request = TimedRequest(inner_request, default_timeout)
    request.get('/foo/bar/123')

    inner_request.perform.assert_called_once_with(
        'GET', '/foo/bar/123', timeout=default_timeout
    )


def test_that_timed_request_overwrites_default_timeout_if_specified():
    inner_request = MagicMock()
    default_timeout = 3.14
    specified_timeout = 2.71

    request = TimedRequest(inner_request, default_timeout)
    request.get('/foo/bar/123', timeout=specified_timeout)

    inner_request.perform.assert_called_once_with(
        'GET', '/foo/bar/123', timeout=specified_timeout
    )
