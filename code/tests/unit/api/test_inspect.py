from api.threatresponse.api.inspect import InspectAPI

from .assertions import *


def test_inspect_succeeds():
    request = invoke(InspectAPI, lambda api: api.inspect(payload))
    request.perform.assert_called_once_with(
        'POST',
        '/iroh/iroh-inspect/inspect',
        json=payload
    )


def test_inspect_fails():
    request = invoke_with_failure(InspectAPI, lambda api: api.inspect(payload))
    request.perform.assert_called_once_with(
        'POST',
        '/iroh/iroh-inspect/inspect',
        json=payload
    )
