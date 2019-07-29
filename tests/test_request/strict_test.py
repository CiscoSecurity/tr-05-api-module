import pytest
from requests import HTTPError
from mock import Mock

from ..common import patch

from threatresponse.request.base import Request
from threatresponse.request.strict import StrictRequest


@patch(Request)
def test_that_strict_request_invokes_inner_request(request):
    strict = StrictRequest(request)
    strict.post('/some')

    request.perform.assert_called_once_with('POST', '/some')


@patch(Request)
def test_that_strict_request_raises_error_when_responded_with_error_code(request):
    def raise_for_status():
        raise HTTPError('Error message.', response=response)

    response = Mock()
    response.raise_for_status.side_effect = raise_for_status
    response.json.return_value = {'error': 'occurred'}

    request.perform.return_value = response

    with pytest.raises(HTTPError):
        strict = StrictRequest(request)
        strict.post('/some')


@patch(Request)
def test_that_strict_request_not_raises_error_when_responded_ok(request):
    def raise_for_status():
        return

    response = Mock()
    response.raise_for_status.side_effect = raise_for_status

    strict = StrictRequest(request)
    strict.post('/some')
