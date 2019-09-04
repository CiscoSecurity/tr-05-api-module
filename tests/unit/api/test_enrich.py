import pytest
from mock import MagicMock

from threatresponse.api import EnrichAPI


def test_health_fails():
    assert_fails(
        lambda api: api.health(),
        url='/iroh/iroh-enrich/health'
    )


def test_deliberate_observables_succeeds():
    assert_succeeds(
        lambda api, payload: api.deliberate.observables(payload),
        payload=[{'ham': 'egg'}],
        url='/iroh/iroh-enrich/deliberate/observables'
    )


def test_deliberate_observables_fails():
    assert_fails(
        lambda api, payload: api.deliberate.observables(payload),
        payload=[{'ham': 'egg'}],
        url='/iroh/iroh-enrich/deliberate/observables'
    )


def test_observe_observables_succeeds():
    assert_succeeds(
        lambda api, payload: api.observe.observables(payload),
        payload=[{'ham': 'egg'}],
        url='/iroh/iroh-enrich/observe/observables'
    )


def test_observe_observables_fails():
    assert_fails(
        lambda api, payload: api.observe.observables(payload),
        payload=[{'ham': 'egg'}],
        url='/iroh/iroh-enrich/observe/observables'
    )


def test_refer_observables_succeeds():
    assert_succeeds(
        lambda api, payload: api.refer.observables(payload),
        payload=[{'ham': 'egg'}],
        url='/iroh/iroh-enrich/refer/observables'
    )


def test_refer_observables_fails():
    assert_fails(
        lambda api, payload: api.refer.observables(payload),
        payload=[{'ham': 'egg'}],
        url='/iroh/iroh-enrich/refer/observables'
    )


def assert_succeeds(invoke, url, payload=None):
    response = MagicMock()

    request = MagicMock()
    request.post.return_value = response

    api = EnrichAPI(request)

    if payload is not None:
        invoke(api, payload)
    else:
        invoke(api)

    if payload is not None:
        request.post.assert_called_once_with(url, json=payload)
    else:
        request.post.assert_called_once_with(url)

    response.json.assert_called_once_with()


def assert_fails(invoke, url, payload=None):
    class TestError(Exception):
        pass

    response = MagicMock()
    response.raise_for_status.side_effect = TestError('Oops!')

    request = MagicMock()
    request.post.return_value = response

    api = EnrichAPI(request)
    with pytest.raises(TestError):
        if payload is not None:
            invoke(api, payload)
        else:
            invoke(api)

    if payload is not None:
        request.post.assert_called_once_with(url, json=payload)
    else:
        request.post.assert_called_once_with(url)

    response.raise_for_status.assert_called_once_with()
