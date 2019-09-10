from mock import MagicMock

from threatresponse.api import IntelAPI


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


def assert_succeeds_with_get(invoke, url, id_=None, **query):
    response, request, api = response_request_and_api()
    request.get.return_value = response
    if id_ and query:
        invoke(api, id_, query)
    elif id_ is None:
        invoke(api, query)
    else:
        invoke(api, id_)
    request.get.assert_called_once_with(url,params=query)
    response.json.assert_called_once_with()


def assert_succeeds_with_post(invoke, url, payload=None):
    response, request, api = response_request_and_api()
    request.post.return_value = response

    if payload is not None:
        invoke(api, payload)
    else:
        invoke(api)

    if payload is not None:
        request.post.assert_called_once_with(url, json=payload)
    else:
        request.post.assert_called_once_with(url)

    response.json.assert_called_once_with()


def assert_succeeds_with_delete(invoke, url, id_):
    response, request, api = response_request_and_api()
    request.delete.return_value = response
    invoke(api, id_)

    request.delete.assert_called_once_with(url)
    response.json.assert_called_once_with()


def assert_succeeds_with_put(invoke, url, id_, payload):
    response, request, api = response_request_and_api()
    request.put.return_value = response
    invoke(api, id_, payload)

    request.put.assert_called_once_with(url, json=payload)
    response.json.assert_called_once_with()


def response_request_and_api():
    response = MagicMock()
    request = MagicMock()
    api = IntelAPI(request)

    return response, request, api
