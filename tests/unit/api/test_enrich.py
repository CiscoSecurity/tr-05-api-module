from threatresponse.api import EnrichAPI

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


def test_health_with_id_succeeds():
    request = invoke(
        EnrichAPI,
        lambda api: api.health.module_instance_id('id')
    )
    request.perform.assert_called_once_with(
        'POST',
        '/iroh/iroh-enrich/health/id'
    )


def test_health_with_id_fails():
    request = invoke_with_failure(
        EnrichAPI,
        lambda api: api.health.module_instance_id('id')
    )
    request.perform.assert_called_once_with(
        'POST',
        '/iroh/iroh-enrich/health/id'
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


def test_deliberate_sighting_succeeds():
    request = invoke(
        EnrichAPI,
        lambda api: api.deliberate.sighting(payload)
    )
    request.perform.assert_called_once_with(
        'POST',
        '/iroh/iroh-enrich/deliberate/sighting',
        json=payload
    )


def test_deliberate_sighting_fails():
    request = invoke_with_failure(
        EnrichAPI,
        lambda api: api.deliberate.sighting(payload)
    )
    request.perform.assert_called_once_with(
        'POST',
        '/iroh/iroh-enrich/deliberate/sighting',
        json=payload
    )


def test_deliberate_sighting_ref_succeeds():
    request = invoke(
        EnrichAPI,
        lambda api: api.deliberate.sighting_ref(payload)
    )
    request.perform.assert_called_once_with(
        'POST',
        '/iroh/iroh-enrich/deliberate/sighting_ref',
        json=payload
    )


def test_deliberate_sighting_ref_fails():
    request = invoke_with_failure(
        EnrichAPI,
        lambda api: api.deliberate.sighting_ref(payload)
    )
    request.perform.assert_called_once_with(
        'POST',
        '/iroh/iroh-enrich/deliberate/sighting_ref',
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


def test_observe_sighting_succeeds():
    request = invoke(EnrichAPI, lambda api: api.observe.sighting(payload))
    request.perform.assert_called_once_with(
        'POST',
        '/iroh/iroh-enrich/observe/sighting',
        json=payload
    )


def test_observe_sighting_fails():
    request = invoke_with_failure(
        EnrichAPI,
        lambda api: api.observe.sighting(payload)
    )
    request.perform.assert_called_once_with(
        'POST',
        '/iroh/iroh-enrich/observe/sighting',
        json=payload
    )


def test_observe_sighting_ref_succeeds():
    request = invoke(EnrichAPI, lambda api: api.observe.sighting_ref(payload))
    request.perform.assert_called_once_with(
        'POST',
        '/iroh/iroh-enrich/observe/sighting_ref',
        json=payload
    )


def test_observe_sighting_ref_fails():
    request = invoke_with_failure(
        EnrichAPI,
        lambda api: api.observe.sighting_ref(payload)
    )
    request.perform.assert_called_once_with(
        'POST',
        '/iroh/iroh-enrich/observe/sighting_ref',
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


def test_refer_sighting_succeeds():
    request = invoke(EnrichAPI, lambda api: api.refer.sighting(payload))
    request.perform.assert_called_once_with(
        'POST',
        '/iroh/iroh-enrich/refer/sighting',
        json=payload
    )


def test_refer_sighting_fails():
    request = invoke_with_failure(
        EnrichAPI,
        lambda api: api.refer.sighting(payload)
    )
    request.perform.assert_called_once_with(
        'POST',
        '/iroh/iroh-enrich/refer/sighting',
        json=payload
    )


def test_refer_sighting_ref_succeeds():
    request = invoke(EnrichAPI, lambda api: api.refer.sighting_ref(payload))
    request.perform.assert_called_once_with(
        'POST',
        '/iroh/iroh-enrich/refer/sighting_ref',
        json=payload
    )


def test_refer_sighting_ref_fails():
    request = invoke_with_failure(
        EnrichAPI,
        lambda api: api.refer.sighting_ref(payload)
    )
    request.perform.assert_called_once_with(
        'POST',
        '/iroh/iroh-enrich/refer/sighting_ref',
        json=payload
    )


def test_settings_succeeds():
    request = invoke(EnrichAPI, lambda api: api.settings.get())
    request.perform.assert_called_once_with(
        'GET',
        '/iroh/iroh-enrich/settings'
    )


def test_settings_fails():
    request = invoke_with_failure(
        EnrichAPI,
        lambda api: api.settings.get()
    )
    request.perform.assert_called_once_with(
        'GET',
        '/iroh/iroh-enrich/settings'
    )
