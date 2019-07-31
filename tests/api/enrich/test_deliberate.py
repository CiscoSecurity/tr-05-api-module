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
