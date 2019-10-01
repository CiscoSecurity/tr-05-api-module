import pytest

from .assertions import *

from threatresponse.api.inspect import InspectAPI


def test_inspect_succeeds():
    request = invoke(lambda api: api.inspect(payload), InspectAPI)
    request.post.assert_called_once_with(
        '/iroh/iroh-inspect/inspect',
        json=payload)


def test_inspect_fails():
    class TestError(Exception):
        pass

    response = MagicMock()
    response.raise_for_status.side_effect = TestError('Oops!')

    request = MagicMock()
    request.post.return_value = response

    api = InspectAPI(request)
    with pytest.raises(TestError):
        api.inspect(payload)

    request.post.assert_called_once_with(
        '/iroh/iroh-inspect/inspect',
        json=payload,
    )

    response.raise_for_status.assert_called_once_with()
