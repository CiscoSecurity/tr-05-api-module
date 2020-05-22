from functools import partial

from threatresponse.api.module_entity import ModuleEntityAPI

from .assertions import *


def module_entity_api(url):
    return partial(ModuleEntityAPI, url=url)


def test_get_succeeds():
    request = invoke(
        module_entity_api('/x'),
        lambda api: api.get()
    )
    request.perform.assert_called_once_with(
        'GET',
        '/x'
    )

    request = invoke(
        module_entity_api('/x'),
        lambda api: api.get(response_type='raw'),
        'raw'
    )
    request.perform.assert_called_once_with(
        'GET',
        '/x'
    )


def test_get_with_id_succeeds():
    request = invoke(
        module_entity_api('/x'),
        lambda api: api.get('42')
    )
    request.perform.assert_called_once_with(
        'GET',
        '/x/42'
    )

    request = invoke(
        module_entity_api('/x'),
        lambda api: api.get('42', response_type='raw'),
        'raw'
    )
    request.perform.assert_called_once_with(
        'GET',
        '/x/42'
    )


def test_get_with_id_and_fields_succeeds():
    params = {'fields': ['schema_version', 'revision']}

    request = invoke(
        module_entity_api('/x'),
        lambda api: api.get('42', params=params)
    )
    request.perform.assert_called_once_with(
        'GET',
        '/x/42',
        params=params
    )

    request = invoke(
        module_entity_api('/x'),
        lambda api: api.get('42', params=params, response_type='raw'),
        'raw'
    )
    request.perform.assert_called_once_with(
        'GET',
        '/x/42',
        params=params
    )


def test_post_succeeds():
    request = invoke(
        module_entity_api('/x'),
        lambda api: api.post(payload)
    )
    request.perform.assert_called_once_with(
        'POST',
        '/x',
        json=payload
    )

    request = invoke(
        module_entity_api('/x'),
        lambda api: api.post(payload, response_type='raw'),
        'raw'
    )
    request.perform.assert_called_once_with(
        'POST',
        '/x',
        json=payload
    )


def test_patch_succeeds():
    request = invoke(
        module_entity_api('/x'),
        lambda api: api.patch('42', payload=payload)
    )
    request.perform.assert_called_once_with(
        'PATCH',
        '/x/42',
        json=payload
    )

    request = invoke(
        module_entity_api('/x'),
        lambda api: api.patch('42', payload=payload, response_type='raw'),
        'raw'
    )
    request.perform.assert_called_once_with(
        'PATCH',
        '/x/42',
        json=payload
    )


def test_delete_succeeds():
    request = invoke(
        module_entity_api('/x'),
        lambda api: api.delete('42'), 'raw'
    )
    request.perform.assert_called_once_with(
        'DELETE',
        '/x/42'
    )
