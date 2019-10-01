from .assertions import *
import pytest

from threatresponse.api import EnrichAPI


def test_health_fails():
    assert_fails(
        lambda api: api.health(),
        url='/iroh/iroh-enrich/health'
    )


def test_deliberate_observables_succeeds():
    request = invoke(lambda api: api.deliberate.observables(payload), EnrichAPI)
    request.post.assert_called_once_with(
        '/iroh/iroh-enrich/deliberate/observables',
        json=payload)


def test_deliberate_observables_fails():
    assert_fails(
        lambda api, payload: api.deliberate.observables(payload),
        payload=[{'ham': 'egg'}],
        url='/iroh/iroh-enrich/deliberate/observables'
    )


def test_observe_observables_succeeds():
    request = invoke(lambda api: api.observe.observables(payload), EnrichAPI)
    request.post.assert_called_once_with(
        '/iroh/iroh-enrich/observe/observables',
        json=payload)


def test_observe_observables_fails():
    assert_fails(
        lambda api, payload: api.observe.observables(payload),
        payload=[{'ham': 'egg'}],
        url='/iroh/iroh-enrich/observe/observables'
    )


def test_refer_observables_succeeds():
    request = invoke(lambda api: api.refer.observables(payload), EnrichAPI)
    request.post.assert_called_once_with(
        '/iroh/iroh-enrich/refer/observables',
        json=payload)


def test_refer_observables_fails():
    assert_fails(
        lambda api, payload: api.refer.observables(payload),
        payload=[{'ham': 'egg'}],
        url='/iroh/iroh-enrich/refer/observables'
    )


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
