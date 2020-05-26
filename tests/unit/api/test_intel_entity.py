from functools import partial

from threatresponse.api.entity import IntelEntityAPI

from .assertions import *


def intel_entity_api(url):
    return partial(IntelEntityAPI, url=url)


def test_get_by_external_id_succeeds():
    request = invoke(intel_entity_api('/x'), lambda api: api.external_id('42'))
    request.perform.assert_called_once_with(
        'GET',
        '/x/external_id/42'
    )

    request = invoke(
        intel_entity_api('/x'),
        lambda api: api.external_id('42', response_type='raw'),
        'raw'
    )
    request.perform.assert_called_once_with(
        'GET',
        '/x/external_id/42'
    )


def test_search_by_id_succeeds():
    params = {'id': 12}

    request = invoke(
        intel_entity_api('/x'),
        lambda api: api.search(params=params)
    )
    request.perform.assert_called_once_with(
        'GET',
        '/x/search',
        params=params
    )

    request = invoke(
        intel_entity_api('/x'),
        lambda api: api.search(params=params, response_type='raw'),
        'raw'
    )
    request.perform.assert_called_once_with(
        'GET',
        '/x/search',
        params=params
    )


def test_search_with_query_succeeds():
    params = {'query': '*'}

    request = invoke(
        intel_entity_api('/x'),
        lambda api: api.search(params=params)
    )
    request.perform.assert_called_once_with(
        'GET',
        '/x/search',
        params=params
    )

    request = invoke(
        intel_entity_api('/x'),
        lambda api: api.search(params=params, response_type='raw'),
        'raw'
    )
    request.perform.assert_called_once_with(
        'GET',
        '/x/search',
        params=params
    )
