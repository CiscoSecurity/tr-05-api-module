from assertions import *


def test_campaign_by_id_succeeds():
    assert_succeeds_with_get(
        lambda api, id_: api.campaign.get(id_),
        id_=12,
        url='/ctia/campaign/12',
    )


def test_campaign_by_id_with_fields_succeeds():
    assert_succeeds_with_get(
        lambda api, id_, query: api.campaign.get(id_, **query),
        id_=12,
        query={'fields': ['schema_version', 'revision']},
        url='/ctia/campaign/12'
    )


def test_campaign_by_external_id_with_fields_succeeds():
    assert_succeeds_with_get(
        lambda api, id_, fields: api.campaign.external_id(id_, **fields),
        id_=12,
        query={'fields': ['schema_version', 'revision']},
        url='/ctia/campaign/external_id/12'
    )


def test_campaign_by_external_id_with_fields_and_query_succeeds():
    assert_succeeds_with_get(
        lambda api, id_, query: api.campaign.external_id(id_, **query),
        id_=12,
        url='/ctia/campaign/external_id/12',
        query={'limit': 12, 'offset': 1, 'fields': ['schema_version', 'revision']}
    )

def test_campaign_by_external_id_succeeds():
    assert_succeeds_with_get(
        lambda api, id_: api.campaign.external_id(id_),
        id_=12,
        url='/ctia/campaign/external_id/12'
    )


def test_campaign_search_succeeds_with_query():
    assert_succeeds_with_get(
        lambda api, query: api.campaign.search(**query),
        query={'id': 12},
        url='/ctia/campaign/search'
        )


def test_create_campaign_success():
    assert_succeeds_with_post(
        lambda api, payload: api.campaign.post(payload),
        payload={'ham': 'egg'},
        url='/ctia/campaign'
    )


def test_delete_campaign_success():
    assert_succeeds_with_delete(
        lambda api, id_: api.campaign.delete(id_),
        id_=12,
        url='/ctia/campaign/12'
    )


def test_update_campaign_success():
    assert_succeeds_with_put(
        lambda api, id_, payload: api.campaign.put(id_, payload),
        id_=12,
        url='/ctia/campaign/12',
        payload={'ham': 'egg'},
    )
