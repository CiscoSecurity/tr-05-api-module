from .assertions import *


def test_coa_by_id_succeeds():
    assert_succeeds_with_get(
        lambda api, id_: api.coa.get(id_),
        id_=12,
        url='/ctia/coa/12',
    )


def test_coa_by_id_with_fields_succeeds():
    assert_succeeds_with_get(
        lambda api, id_, query: api.coa.get(id_, **query),
        id_=12,
        query={'fields': ['schema_version', 'revision']},
        url='/ctia/coa/12'
    )


def test_coa_by_external_id_with_fields_succeeds():
    assert_succeeds_with_get(
        lambda api, id_, fields: api.coa.external_id(id_, **fields),
        id_=12,
        query={'fields': ['schema_version', 'revision']},
        url='/ctia/coa/external_id/12'
    )


def test_coa_by_external_id_with_fields_and_query_succeeds():
    assert_succeeds_with_get(
        lambda api, id_, query: api.coa.external_id(id_, **query),
        id_=12,
        url='/ctia/coa/external_id/12',
        query={'limit': 12, 'offset': 1, 'fields': ['schema_version', 'revision']}
    )


def test_coa_by_external_id_succeeds():
    assert_succeeds_with_get(
        lambda api, id_: api.coa.external_id(id_),
        id_=12,
        url='/ctia/coa/external_id/12'
    )


def test_coa_search_succeeds_with_query():
    assert_succeeds_with_get(
        lambda api, query: api.coa.search(**query),
        query={'id': 12},
        url='/ctia/coa/search'
        )


def test_create_coa_success():
    assert_succeeds_with_post(
        lambda api, payload: api.coa.post(payload),
        payload={'ham': 'egg'},
        url='/ctia/coa'
    )


def test_delete_coa_success():
    assert_succeeds_with_delete(
        lambda api, id_: api.coa.delete(id_),
        id_=12,
        url='/ctia/coa/12'
    )


def test_update_coa_success():
    assert_succeeds_with_put(
        lambda api, id_, payload: api.coa.put(id_, payload),
        id_=12,
        url='/ctia/coa/12',
        payload={'ham': 'egg'},
    )

