from .assertions import *

from threatresponse.api import EnrichAPI


def test_health_succeeds():
    request = invoke(lambda api: api.health(), EnrichAPI)
    request.post.assert_called_once_with(
        '/iroh/iroh-enrich/health')


def test_health_fails():
    request = invoke_with_failure(lambda api: api.health(), EnrichAPI)
    request.post.assert_called_once_with(
        '/iroh/iroh-enrich/health')


def test_deliberate_observables_succeeds():
    request = invoke(lambda api: api.deliberate.observables(payload), EnrichAPI)
    request.post.assert_called_once_with(
        '/iroh/iroh-enrich/deliberate/observables',
        json=payload)


def test_deliberate_observables_fails():
    request = invoke_with_failure(lambda api: api.deliberate.observables(payload), EnrichAPI)
    request.post.assert_called_once_with(
        '/iroh/iroh-enrich/deliberate/observables',
        json=payload)


def test_observe_observables_succeeds():
    request = invoke(lambda api: api.observe.observables(payload), EnrichAPI)
    request.post.assert_called_once_with(
        '/iroh/iroh-enrich/observe/observables',
        json=payload)


def test_observe_observables_fails():
    request = invoke_with_failure(lambda api: api.observe.observables(payload), EnrichAPI)
    request.post.assert_called_once_with(
        '/iroh/iroh-enrich/observe/observables',
        json=payload)


def test_refer_observables_succeeds():
    request = invoke(lambda api: api.refer.observables(payload), EnrichAPI)
    request.post.assert_called_once_with(
        '/iroh/iroh-enrich/refer/observables',
        json=payload)


def test_refer_observables_fails():
    request = invoke_with_failure(lambda api: api.refer.observables(payload), EnrichAPI)
    request.post.assert_called_once_with(
        '/iroh/iroh-enrich/refer/observables',
        json=payload)
