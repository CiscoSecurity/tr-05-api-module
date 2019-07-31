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


def test_sighting():
    request = MagicMock()
    payload = {'foo': 'bar'}

    api = ObserveAPI(request)
    api.sighting(payload)

    request.post.assert_called_once_with(
        '/iroh/iroh-enrich/observe/sighting', json=payload
    )


def test_sighting_ref():
    request = MagicMock()
    payload = 'foo'

    api = ObserveAPI(request)
    api.sighting_ref(payload)

    request.post.assert_called_once_with(
        '/iroh/iroh-enrich/observe/sighting_ref', json=payload
    )
