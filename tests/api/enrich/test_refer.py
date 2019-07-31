from mock import MagicMock

from threatresponse.api.enrich.refer import ReferAPI


def test_observables():
    request = MagicMock()
    payload = [
        {'value': 'string',
         'type': 'file_path'}
    ]

    api = ReferAPI(request)
    api.observables(payload)

    request.post.assert_called_once_with(
        '/iroh/iroh-enrich/refer/observables', json=payload
    )


def test_sighting():
    request = MagicMock()
    payload = {'hello': 'world'}

    api = ReferAPI(request)
    api.sighting(payload)

    request.post.assert_called_once_with(
        '/iroh/iroh-enrich/refer/sighting', json=payload
    )


def test_sighting_ref():
    request = MagicMock()
    payload = 'hello world'

    api = ReferAPI(request)
    api.sighting_ref(payload)

    request.post.assert_called_once_with(
        '/iroh/iroh-enrich/refer/sighting_ref', json=payload
    )
