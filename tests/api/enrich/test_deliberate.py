from mock import MagicMock

from threatresponse.api.enrich.deliberate import DeliberateAPI


def test_observables():
    request = MagicMock()
    payload = [{'foo': 'bar'}]

    api = DeliberateAPI(request)
    api.observables(payload)

    request.post.assert_called_once_with(
        '/iroh/iroh-enrich/deliberate/observables', json=payload
    )


def test_sighting():
    request = MagicMock()
    payload = {'foo': 'bar'}

    api = DeliberateAPI(request)
    api.sighting(payload)

    request.post.assert_called_once_with(
        '/iroh/iroh-enrich/deliberate/sighting', json=payload
    )


def test_sighting_ref():
    request = MagicMock()
    payload = 'foo'

    api = DeliberateAPI(request)
    api.sighting_ref(payload)

    request.post.assert_called_once_with(
        '/iroh/iroh-enrich/deliberate/sighting_ref', json=payload
    )
