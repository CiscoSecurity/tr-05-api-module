from functools import partial

from api.threatresponse.api.entity import EntityAPI

from .assertions import *


def entity_api(url):
    return partial(EntityAPI, url=url)


def test_get_succeeds():
    request = invoke(entity_api('/x'), lambda api: api.get())
    request.perform.assert_called_once_with(
        'GET',
        '/x'
    )

    request = invoke(entity_api('/x'),
                     lambda api: api.get(response_type='raw'),
                     'raw')
    request.perform.assert_called_once_with(
        'GET',
        '/x'
    )


def test_get_with_id_succeeds():
    request = invoke(entity_api('/x'), lambda api: api.get('42'))
    request.perform.assert_called_once_with(
        'GET',
        '/x/42'
    )

    request = invoke(entity_api('/x'),
                     lambda api: api.get('42', response_type='raw'),
                     'raw')
    request.perform.assert_called_once_with(
        'GET',
        '/x/42'
    )


def test_get_with_id_and_fields_succeeds():
    params = {'fields': ['schema_version', 'revision']}

    request = invoke(entity_api('/x'),
                     lambda api: api.get('42', params=params))
    request.perform.assert_called_once_with(
        'GET',
        '/x/42',
        params=params
    )

    request = invoke(entity_api('/x'),
                     lambda api: api.get('42',
                                         params=params,
                                         response_type='raw'),
                     'raw')
    request.perform.assert_called_once_with(
        'GET',
        '/x/42',
        params=params
    )


def test_post_succeeds():
    request = invoke(entity_api('/x'), lambda api: api.post(payload))
    request.perform.assert_called_once_with(
        'POST',
        '/x',
        json=payload
    )

    request = invoke(entity_api('/x'),
                     lambda api: api.post(payload, response_type='raw'),
                     'raw')
    request.perform.assert_called_once_with(
        'POST',
        '/x',
        json=payload
    )


def test_delete_succeeds():
    request = invoke(entity_api('/x'), lambda api: api.delete('42'), 'raw')
    request.perform.assert_called_once_with(
        'DELETE',
        '/x/42'
    )


def test_put_succeeds():
    request = invoke(entity_api('/x'), lambda api: api.put('12', payload))
    request.perform.assert_called_once_with(
        'PUT',
        '/x/12',
        json=payload
    )

    request = invoke(entity_api('/x'),
                     lambda api: api.put('12', payload, response_type='raw'),
                     'raw')
    request.perform.assert_called_once_with(
        'PUT',
        '/x/12',
        json=payload
    )
