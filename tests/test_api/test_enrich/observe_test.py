from mock import MagicMock

from threatresponse.api.enrich.observe import ObserveAPI


def test_observables():
    payload = [{'foo': 'bar'}]

    request = MagicMock()
    api = ObserveAPI(request)
    api.observables(payload)

    request.post.assert_called_once_with(
        '/iroh/iroh-enrich/observe/observables', json=payload)


def test_sighting():
    payload = {'foo': 'bar'}

    request = MagicMock()
    api = ObserveAPI(request)
    api.sighting(payload)

    request.post.assert_called_once_with(
        '/iroh/iroh-enrich/observe/sighting', json=payload)


def test_sighting_ref():
    payload = 'foo'

    request = MagicMock()
    api = ObserveAPI(request)
    api.sighting_ref(payload)

    request.post.assert_called_once_with(
        '/iroh/iroh-enrich/observe/sighting_ref', json=payload)
