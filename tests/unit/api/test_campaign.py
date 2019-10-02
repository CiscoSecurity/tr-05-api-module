from .assertions import *


def test_campaign_by_id_with_fields_succeeds():
    request = invoke(lambda api: api.campaign.get(
        12, fields=['schema_version', 'revision']))
    request.get.assert_called_once_with(
        '/ctia/campaign/12',
        params={'fields': ['schema_version', 'revision']})


def test_campaign_by_external_id_with_fields_succeeds():
    request = invoke(lambda api: api.campaign.external_id(
        12, fields=['schema_version', 'revision']))
    request.get.assert_called_once_with(
        '/ctia/campaign/external_id/12',
        params={'fields': ['schema_version', 'revision']})


def test_campaign_search_succeeds_with_query():
    request = invoke(lambda api: api.campaign.search(id=12))
    request.get.assert_called_once_with(
        '/ctia/campaign/search',
        params={'id': 12})


def test_create_campaign_success():
    request = invoke(lambda api: api.campaign.post(payload))
    request.post.assert_called_once_with(
        '/ctia/campaign',
        json=payload,
        params={})


def test_delete_campaign_success():
    request = invoke(lambda api: api.campaign.delete(12))
    request.delete.assert_called_once_with(
        '/ctia/campaign/12')


def test_update_campaign_success():
    request = invoke(lambda api: api.campaign.put(12, payload))
    request.put.assert_called_once_with(
        '/ctia/campaign/12',
        json=payload)
