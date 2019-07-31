from mock import MagicMock

from threatresponse.api.inspect import InspectAPI


def test_inspect():
    request = MagicMock()
    payload = {'foo': 'bar'}

    api = InspectAPI(request)
    api.inspect(payload)

    request.post.assert_called_once_with(
        '/iroh/iroh-inspect/inspect', json=payload
    )
