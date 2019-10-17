from mock import MagicMock
from pytest import raises


payload = {'ham': 'eggs'}


def invoke(api, invocation, response_type='json'):
    request, response = MagicMock(), MagicMock()

    for method in ['get', 'post', 'patch', 'put', 'delete', 'perform']:
        method = getattr(request, method)
        method.return_value = response

    invocation(api(request))

    if response_type == 'raw':
        response.json.assert_not_called()
    if response_type == 'json':
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
