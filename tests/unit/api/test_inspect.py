from .assertions import *

from threatresponse.api.inspect import InspectAPI


def test_inspect_succeeds():
    request = invoke(lambda api: api.inspect(payload), InspectAPI)
    request.post.assert_called_once_with(
        '/iroh/iroh-inspect/inspect',
        json=payload)


def test_inspect_fails():
    request = invoke_with_failure(lambda api: api.inspect(payload), InspectAPI)
    request.post.assert_called_once_with(
        '/iroh/iroh-inspect/inspect',
        json=payload)
