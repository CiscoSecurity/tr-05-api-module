from functools import partial

from threatresponse.api.entity import EntityAPI

from .assertions import *


def entity_api(url):
    return partial(EntityAPI, url=url)


def test_get_succeeds():
    request = invoke(entity_api('/x'), lambda api: api.get())
    request.perform.assert_called_once_with(
        'GET',
        '/x',
        params={}
    )

    request = invoke(entity_api('/x'),
                     lambda api: api.get(response_type='raw'),
                     'raw')
    request.perform.assert_called_once_with(
        'GET',
        '/x',
        params={}
    )


def test_get_with_id_succeeds():
    request = invoke(entity_api('/x'), lambda api: api.get(42))
    request.perform.assert_called_once_with(
        'GET',
        '/x/42',
        params={}
    )

    request = invoke(entity_api('/x'),
                     lambda api: api.get(42, response_type='raw'),
                     'raw')
    request.perform.assert_called_once_with(
        'GET',
        '/x/42',
        params={}
    )


def test_get_with_id_and_fields_succeeds():
    fields = ['schema_version', 'revision']

    request = invoke(entity_api('/x'), lambda api: api.get(42, fields=fields))
    request.perform.assert_called_once_with(
        'GET',
        '/x/42',
        params={'fields': fields}
    )

    request = invoke(entity_api('/x'),
                     lambda api: api.get(42, fields=fields,
                                         response_type='raw'),
                     'raw')
    request.perform.assert_called_once_with(
        'GET',
        '/x/42',
        params={'fields': fields}
    )


def test_post_succeeds():
    request = invoke(entity_api('/x'), lambda api: api.post(payload))
    request.perform.assert_called_once_with(
        'POST',
        '/x',
        json=payload,
        params={}
    )

    request = invoke(entity_api('/x'),
                     lambda api: api.post(payload, response_type='raw'),
                     'raw')
    request.perform.assert_called_once_with(
        'POST',
        '/x',
        json=payload,
        params={}
    )


def test_delete_succeeds():
    request = invoke(entity_api('/x'), lambda api: api.delete(42), 'raw')
    request.perform.assert_called_once_with(
        'DELETE',
        '/x/42'
    )


def test_put_succeeds():
    request = invoke(entity_api('/x'), lambda api: api.put(12, payload))
    request.perform.assert_called_once_with(
        'PUT',
        '/x/12',
        json=payload
    )

    request = invoke(entity_api('/x'),
                     lambda api: api.put(12, payload, response_type='raw'),
                     'raw')
    request.perform.assert_called_once_with(
        'PUT',
        '/x/12',
        json=payload
    )


def test_get_by_external_id_succeeds():
    request = invoke(entity_api('/x'), lambda api: api.external_id(42))
    request.perform.assert_called_once_with(
        'GET',
        '/x/external_id/42',
        params={}
    )

    request = invoke(entity_api('/x'),
                     lambda api: api.external_id(42, response_type='raw'),
                     'raw')
    request.perform.assert_called_once_with(
        'GET',
        '/x/external_id/42',
        params={}
    )


def test_search_by_id_succeeds():
    request = invoke(entity_api('/x'), lambda api: api.search(id=12))
    request.perform.assert_called_once_with(
        'GET',
        '/x/search',
        params={'id': 12}
    )

    request = invoke(entity_api('/x'),
                     lambda api: api.search(id=12, response_type='raw'),
                     'raw')
    request.perform.assert_called_once_with(
        'GET',
        '/x/search',
        params={'id': 12}
    )


def test_search_with_query_succeeds():
    request = invoke(entity_api('/x'), lambda api: api.search(query='*'))
    request.perform.assert_called_once_with(
        'GET',
        '/x/search',
        params={'query': '*'}
    )

    request = invoke(entity_api('/x'),
                     lambda api: api.search(query='*', response_type='raw'),
                     'raw')
    request.perform.assert_called_once_with(
        'GET',
        '/x/search',
        params={'query': '*'}
    )
