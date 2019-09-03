import pytest
from mock import MagicMock

from threatresponse.api import EnrichAPI


def test_health_fails():
    class TestError(Exception):
        pass

    response = MagicMock()
    response.raise_for_status.side_effect = TestError('Oops!')

    request = MagicMock()
    request.post.return_value = response

    api = EnrichAPI(request)
    with pytest.raises(TestError):
        api.health()

    request.post.assert_called_once_with('/iroh/iroh-enrich/health')

    response.raise_for_status.assert_called_once_with()


def test_deliberate_observables_succeeds():
    assert_succeeds(
        lambda api, payload: api.deliberate.observables(payload),
        '/iroh/iroh-enrich/deliberate/observables'
    )


def test_deliberate_observables_fails():
    assert_fails(
        lambda api, payload: api.deliberate.observables(payload),
        '/iroh/iroh-enrich/deliberate/observables'
    )


def test_observe_observables_succeeds():
    assert_succeeds(
        lambda api, payload: api.observe.observables(payload),
        '/iroh/iroh-enrich/observe/observables'
    )


def test_observe_observables_fails():
    assert_fails(
        lambda api, payload: api.observe.observables(payload),
        '/iroh/iroh-enrich/observe/observables'
    )


def test_refer_observables_succeeds():
    assert_succeeds(
        lambda api, payload: api.refer.observables(payload),
        '/iroh/iroh-enrich/refer/observables'
    )


def test_refer_observables_fails():
    assert_fails(
        lambda api, payload: api.refer.observables(payload),
        '/iroh/iroh-enrich/refer/observables'
    )


def assert_succeeds(invoke, url):
    response = MagicMock()

    request = MagicMock()
    request.post.return_value = response

    payload = [{'foo': 'bar'}]

    api = EnrichAPI(request)
    invoke(api, payload)

    request.post.assert_called_once_with(
        url,
        json=payload,
    )

    response.json.assert_called_once_with()


def assert_fails(invoke, url):
    class TestError(Exception):
        pass

    response = MagicMock()
    response.raise_for_status.side_effect = TestError('Oops!')

    request = MagicMock()
    request.post.return_value = response

    payload = [{'foo': 'bar'}]

    api = EnrichAPI(request)
    with pytest.raises(TestError):
        invoke(api, payload)

    request.post.assert_called_once_with(
        url,
        json=payload,
    )

    response.raise_for_status.assert_called_once_with()

