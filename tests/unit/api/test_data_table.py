from assertions import *


def test_data_table_by_id_succeeds():
    assert_succeeds_with_get(
        lambda api, id_: api.data_table.get(id_),
        id_=12,
        url='/ctia/data-table/12',
    )


def test_data_table_by_id_with_fields_succeeds():
    assert_succeeds_with_get(
        lambda api, id_, query: api.data_table.get(id_, **query),
        id_=12,
        query={'fields': ['schema_version', 'revision']},
        url='/ctia/data-table/12'
    )


def test_data_table_by_external_id_with_fields_succeeds():
    assert_succeeds_with_get(
        lambda api, id_, fields: api.data_table.external_id(id_, **fields),
        id_=12,
        query={'fields': ['schema_version', 'revision']},
        url='/ctia/data-table/external_id/12'
    )


def test_data_table_by_external_id_with_fields_and_query_succeeds():
    assert_succeeds_with_get(
        lambda api, id_, query: api.data_table.external_id(id_, **query),
        id_=12,
        url='/ctia/data-table/external_id/12',
        query={'limit': 12, 'offset': 1, 'fields': ['schema_version', 'revision']}
    )


def test_data_table_by_external_id_succeeds():
    assert_succeeds_with_get(
        lambda api, id_: api.data_table.external_id(id_),
        id_=12,
        url='/ctia/data-table/external_id/12'
    )


def test_create_data_table_success():
    assert_succeeds_with_post(
        lambda api, payload: api.data_table.post(payload),
        payload={'ham': 'egg'},
        url='/ctia/data-table'
    )


def test_delete_data_table_success():
    assert_succeeds_with_delete(
        lambda api, id_: api.data_table.delete(id_),
        id_=12,
        url='/ctia/data-table/12'
    )

