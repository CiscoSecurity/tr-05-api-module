import pytest
from mock import MagicMock

from threatresponse.api import CampaignAPI


def test_campaign_by_id_succeeds():
    assert_succeeds_with_get(
        lambda api, id_: api.campaign_by_id(id_),
        id_=12,
        url='/ctia/campaign/12'
    )


def test_campaign_by_id_with_fields_succeeds():
    assert_succeeds_with_get(
        lambda api, id_, fields: api.campaign_by_id(id_, fields),
        id_=12,
        fields=['schema_version', 'revision'],
        url='/ctia/campaign/12?fields=schema_version&fields=revision&'
    )


def test_campaign_by_external_id_with_fields_succeeds():
    assert_succeeds_with_get(
        lambda api, id_, fields: api.campaign.external_id(id_,fields),
        id_=12,
        fields=['schema_version', 'revision'],
        url='/ctia/campaign/external_id/12?fields=schema_version&fields=revision&'
    )


def test_campaign_by_external_id_with_fields_and_query_succeeds():
    assert_succeeds_with_get(
        lambda api, id_, fields, query: api.campaign.external_id(id_,fields, query),
        id_=12,
        fields=['schema_version', 'revision'],
        url='/ctia/campaign/external_id/12?fields=schema_version&fields=revision&limit=12&offset=1',
        query={'limit': 12, 'offset': 1}
    )


def test_campaign_by_external_id_with_query_succeeds():
    assert_succeeds_with_get(
        lambda api, id_, query: api.campaign.external_id(id_, query=query),
        id_=12,
        url='/ctia/campaign/external_id/12?limit=12&offset=1',
        query={'limit': 12, 'offset': 1}
    )


def test_campaign_by_external_id_succeeds():
    assert_succeeds_with_get(
        lambda api, id_: api.campaign.external_id(id_),
        id_=12,
        url='/ctia/campaign/external_id/12'
    )


# def test_campaign_search_succeeds():
#     assert_succeeds_with_get(
#         lambda api, id_: api.campaign.search(id_),
#         id_=12,
#         url='/ctia/campaign/12'
#     )


# def test_campaign_by_id_with_fields_succeeds():
#     assert_succeeds_with_get(
#         lambda api, id_, fields: api.delete_campaign(id_, fields),
#         id_=12,
#         fields={'data[]': ['schema_version', 'revision']},
#         url='/ctia/campaign'
#     )
# def test_deliberate_observables_fails():
#     assert_fails(
#         lambda api, payload: api.deliberate.observables(payload),
#         payload=[{'ham': 'egg'}],
#         url='/iroh/iroh-enrich/deliberate/observables'
#     )
#
#
# def test_observe_observables_succeeds():
#     assert_succeeds(
#         lambda api, payload: api.observe.observables(payload),
#         payload=[{'ham': 'egg'}],
#         url='/iroh/iroh-enrich/observe/observables'
#     )
#
#
# def test_observe_observables_fails():
#     assert_fails(
#         lambda api, payload: api.observe.observables(payload),
#         payload=[{'ham': 'egg'}],
#         url='/iroh/iroh-enrich/observe/observables'
#     )
#
#
# def test_refer_observables_succeeds():
#     assert_succeeds(
#         lambda api, payload: api.refer.observables(payload),
#         payload=[{'ham': 'egg'}],
#         url='/iroh/iroh-enrich/refer/observables'
#     )
#
#
# def test_refer_observables_fails():
#     assert_fails(
#         lambda api, payload: api.refer.observables(payload),
#         payload=[{'ham': 'egg'}],
#         url='/iroh/iroh-enrich/refer/observables'
#     )


def assert_succeeds_with_get(invoke, url, id_=None, fields=None, query=None):
    response = MagicMock()

    request = MagicMock()
    request.get.return_value = response

    api = CampaignAPI(request)
    if fields and query:
        invoke(api, id_,fields,query)
    elif fields:
        invoke(api, id_, fields)
    elif query:
        invoke(api, id_, query)
    else:
        invoke(api, id_)
    request.get.assert_called_once_with(url)
    response.json.assert_called_once_with()


def assert_fails_with_get(invoke, url, id_=None, fields=None):
    class TestError(Exception):
        pass

    response = MagicMock()
    response.raise_for_status.side_effect = TestError('Oops!')

    request = MagicMock()
    request.post.return_value = response

    api = CampaignAPI(request)
    invoke(api)
    request.get.assert_called_once_with(url)
    response.raise_for_status.assert_called_once_with()

if __name__ == '__main__':
    test_campaign_by_id_succeeds()