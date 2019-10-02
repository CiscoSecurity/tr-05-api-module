from mock import MagicMock
import pytest

from threatresponse.api import IntelAPI


payload = {'ham': 'eggs'}


def invoke(invocation, api=None):
    request, response = MagicMock(), MagicMock()

    for method in ['get', 'post', 'patch', 'put', 'delete', 'perform']:
        method = getattr(request, method)
        method.return_value = response

    if api:
        invocation(api(request))
    else:
        invocation(IntelAPI(request))

    # Assertions.
    # Since DELETE do not trigger json we need this statement here.
    if request.delete.call_count > 0:
        return request
    else:
        response.json.assert_called_once()
        return request


def invoke_with_failure(invocation, api=None):
    class TestError(Exception):
        pass

    request, response = MagicMock(), MagicMock()
    response.raise_for_status.side_effect = TestError('Oops!')

    for method in ['get', 'post', 'patch', 'put', 'delete', 'perform']:
        method = getattr(request, method)
        method.return_value = response

    if api:
        with pytest.raises(TestError):
            invocation(api(request))
    else:
        with pytest.raises(TestError):
            invocation(IntelAPI(request))
    response.raise_for_status.assert_called_once_with()
    return request
