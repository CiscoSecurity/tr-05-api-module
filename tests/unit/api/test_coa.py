from .assertions import *


def test_coa_by_id_succeeds():
    request = invoke(lambda api: api.coa.get(12))
    request.get.assert_called_once_with(
        '/ctia/coa/12', params={})


def test_coa_by_id_with_fields_succeeds():
    request = invoke(lambda api: api.coa.get(12, fields=['schema_version', 'revision']))
    request.get.assert_called_once_with(
        '/ctia/coa/12', params={'fields': ['schema_version', 'revision']})


def test_coa_by_external_id_succeeds():
    request = invoke(lambda api: api.coa.external_id(12))
    request.get.assert_called_once_with(
        '/ctia/coa/external_id/12', params={})


def test_coa_search_succeeds_with_query():
    request = invoke(lambda api: api.coa.search(id=12))
    request.get.assert_called_once_with(
        '/ctia/coa/search', params={'id': 12})


def test_create_coa_success():
    request = invoke(lambda api: api.coa.post(payload))
    request.post.assert_called_once_with(
        '/ctia/coa',
        json=payload,
        params={})


def test_delete_coa_success():
    request = invoke(lambda api: api.coa.delete(12))
    request.delete.assert_called_once_with(
        '/ctia/coa/12')


def test_update_coa_success():
    request = invoke(lambda api: api.coa.put(12, payload))
    request.put.assert_called_once_with(
        '/ctia/coa/12',
        json=payload)
