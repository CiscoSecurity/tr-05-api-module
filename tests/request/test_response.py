import pytest
from mock import MagicMock
from requests import HTTPError

from threatresponse.request.response import Response


def test_that_getattr_and_setattr_are_delegated():
    inner_response = MagicMock()

    response = Response(inner_response)
    response.foo = 'bar'
    response.spam('eggs')

    assert inner_response.foo == 'bar'
    inner_response.spam.assert_called_once_with('eggs')


def test_that_raise_for_status_extends_error_message():
    inner_response = MagicMock()
    inner_response.json.return_value = {'foo': 'bar', 'spam': ['eggs']}

    error = HTTPError('Something went wrong.')
    error.response = inner_response

    inner_response.raise_for_status.side_effect = error

    response = Response(inner_response)
    with pytest.raises(HTTPError):
        response.raise_for_status()

    inner_response.raise_for_status.assert_called_once_with()
    inner_response.json.assert_called_once_with()
    assert error.args == (
        'Something went wrong.\n'
        '{\n'
        '    "foo": "bar",\n'
        '    "spam": [\n'
        '        "eggs"\n'
        '    ]\n'
        '}',
    )
