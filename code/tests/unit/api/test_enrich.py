from api.threatresponse.api import EnrichAPI

from .assertions import *


def test_health_succeeds():
    request = invoke(EnrichAPI, lambda api: api.health())
    request.perform.assert_called_once_with(
        'POST',
        '/iroh/iroh-enrich/health'
    )


def test_health_fails():
    request = invoke_with_failure(EnrichAPI, lambda api: api.health())
    request.perform.assert_called_once_with(
        'POST',
        '/iroh/iroh-enrich/health'
    )


def test_deliberate_observables_succeeds():
    request = invoke(
        EnrichAPI,
        lambda api: api.deliberate.observables(payload)
    )
    request.perform.assert_called_once_with(
        'POST',
        '/iroh/iroh-enrich/deliberate/observables',
        json=payload
    )


def test_deliberate_observables_fails():
    request = invoke_with_failure(
        EnrichAPI,
        lambda api: api.deliberate.observables(payload)
    )
    request.perform.assert_called_once_with(
        'POST',
        '/iroh/iroh-enrich/deliberate/observables',
        json=payload
    )


def test_observe_observables_succeeds():
    request = invoke(EnrichAPI, lambda api: api.observe.observables(payload))
    request.perform.assert_called_once_with(
        'POST',
        '/iroh/iroh-enrich/observe/observables',
        json=payload
    )


def test_observe_observables_fails():
    request = invoke_with_failure(
        EnrichAPI,
        lambda api: api.observe.observables(payload)
    )
    request.perform.assert_called_once_with(
        'POST',
        '/iroh/iroh-enrich/observe/observables',
        json=payload
    )


def test_refer_observables_succeeds():
    request = invoke(EnrichAPI, lambda api: api.refer.observables(payload))
    request.perform.assert_called_once_with(
        'POST',
        '/iroh/iroh-enrich/refer/observables',
        json=payload
    )


def test_refer_observables_fails():
    request = invoke_with_failure(
        EnrichAPI,
        lambda api: api.refer.observables(payload)
    )
    request.perform.assert_called_once_with(
        'POST',
        '/iroh/iroh-enrich/refer/observables',
        json=payload
    )
