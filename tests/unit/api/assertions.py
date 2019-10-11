from mock import MagicMock
from pytest import raises


payload = {'ham': 'eggs'}


def invoke(api, invocation):
    request, response = MagicMock(), MagicMock()

    for method in ['get', 'post', 'patch', 'put', 'delete', 'perform']:
        method = getattr(request, method)
        method.return_value = response

    invocation(api(request))

    # Assertions.
    # Since DELETE do not trigger json we need this statement here.
    if request.delete.call_count > 0:
        return request
    else:
        response.json.assert_called_once()
        return request


def invoke_with_failure(api, invocation):
    class TestError(Exception):
        pass

    request, response = MagicMock(), MagicMock()
    response.raise_for_status.side_effect = TestError('Oops!')

    for method in ['get', 'post', 'patch', 'put', 'delete', 'perform']:
        method = getattr(request, method)
        method.return_value = response

    with raises(TestError):
        invocation(api(request))

    response.raise_for_status.assert_called_once_with()
    return request
