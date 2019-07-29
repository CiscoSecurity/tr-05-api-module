import pytest
from mock import Mock, MagicMock
from requests import HTTPError

from threatresponse.request.strict import StrictRequest


def test_that_strict_request_invokes_inner_request():
    request = MagicMock()
    strict = StrictRequest(request)
    strict.post('/some')

    request.perform.assert_called_once_with('POST', '/some')


def test_that_strict_request_raises_error_when_responded_with_error_code():
    def raise_for_status():
        raise HTTPError('Error message.', response=response)

    response = Mock()
    response.raise_for_status.side_effect = raise_for_status
    response.json.return_value = {'error': 'occurred'}

    request = MagicMock()
    request.perform.return_value = response

    with pytest.raises(HTTPError):
        strict = StrictRequest(request)
        strict.post('/some')

    response.raise_for_status.assert_called_once()


def test_that_strict_request_not_raises_error_when_responded_ok():
    def raise_for_status():
        return

    response = Mock()
    response.raise_for_status.side_effect = raise_for_status

    request = MagicMock()
    request.perform.return_value = response

    strict = StrictRequest(request)
    strict.post('/some')

    response.raise_for_status.assert_called_once()
