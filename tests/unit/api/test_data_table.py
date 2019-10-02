from .assertions import *


def test_data_table_by_id_succeeds():
    request = invoke(lambda api: api.data_table.get(12,fields=['schema_version', 'revision']))
    request.get.assert_called_once_with(
        '/ctia/data-table/12', params={'fields': ['schema_version', 'revision']})


def test_data_table_by_external_id_with_fields_succeeds():
    request = invoke(lambda api: api.data_table.external_id(12,fields=['schema_version', 'revision']))
    request.get.assert_called_once_with(
        '/ctia/data-table/external_id/12', params={'fields': ['schema_version', 'revision']})

def test_create_coa_success():
    request = invoke(lambda api: api.data_table.post(payload))
    request.post.assert_called_once_with(
        '/ctia/data-table',
        json=payload,
        params={})


def test_delete_data_table_success():
    request = invoke(lambda api: api.data_table.delete(12))
    request.delete.assert_called_once_with(
        '/ctia/data-table/12')
