from mock import MagicMock

from threatresponse.api.enrich.observe import ObserveAPI


def test_observables():
    request = MagicMock()
    payload = [{'foo': 'bar'}]

    api = ObserveAPI(request)
    api.observables(payload)

    request.post.assert_called_once_with(
        '/iroh/iroh-enrich/observe/observables', json=payload
    )
