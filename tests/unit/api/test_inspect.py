import pytest
from mock import MagicMock

from threatresponse.api.inspect import InspectAPI


def test_inspect_succeeds():
    response = MagicMock()

    request = MagicMock()
    request.post.return_value = response

    payload = {'foo': 'bar'}

    api = InspectAPI(request)
    api.inspect(payload)

    request.post.assert_called_once_with(
        '/iroh/iroh-inspect/inspect',
        json=payload,
    )

    response.json.assert_called_once_with()


def test_inspect_fails():
    class TestError(Exception):
        pass

    response = MagicMock()
    response.raise_for_status.side_effect = TestError('Oops!')

    request = MagicMock()
    request.post.return_value = response

    payload = {'foo': 'bar'}

    api = InspectAPI(request)
    with pytest.raises(TestError):
        api.inspect(payload)

    request.post.assert_called_once_with(
        '/iroh/iroh-inspect/inspect',
        json=payload,
    )

    response.raise_for_status.assert_called_once_with()
