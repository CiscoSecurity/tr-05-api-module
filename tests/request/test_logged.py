import pytest
from mock import MagicMock

from threatresponse.request.logged import LoggedRequest


def test_that_logged_request_logs_success():
    inner_request = MagicMock()
    inner_request.perform.return_value = response(200)

    logger = MagicMock()

    request = LoggedRequest(inner_request, logger)
    request.get('/foo/bar/123')

    inner_request.perform.assert_called_once_with('GET', '/foo/bar/123')

    logger.info.assert_called_once_with('GET /foo/bar/123 200 OK')


def test_that_logged_request_logs_error_when_response_fails():
    inner_request = MagicMock()
    inner_request.perform.return_value = response(404)

    logger = MagicMock()

    request = LoggedRequest(inner_request, logger)
    request.get('/foo/bar/123')

    inner_request.perform.assert_called_once_with('GET', '/foo/bar/123')

    logger.error.assert_called_once_with('GET /foo/bar/123 404 Not Found')


def test_that_logged_request_logs_error_when_exception_occurs():
    class TestError(Exception):
        pass

    inner_request = MagicMock()
    inner_request.perform.side_effect = TestError('Something went wrong.')

    logger = MagicMock()

    request = LoggedRequest(inner_request, logger)

    with pytest.raises(TestError):
        request.get('/foo/bar/123')

    inner_request.perform.assert_called_once_with('GET', '/foo/bar/123')

    logger.exception.assert_called_once_with('GET /foo/bar/123')


def response(status_code):
    mocked = MagicMock()
    mocked.status_code = status_code
    mocked.ok = 100 <= status_code < 400

    return mocked
