from mock import MagicMock

from threatresponse.api import COAAPI


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
    api = COAAPI(request)

    return response, request, api
