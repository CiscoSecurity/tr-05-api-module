from mock import MagicMock

from threatresponse.api import IntelAPI


def assert_succeeds_with_get(invoke, url, id_=None, **query):
    response, request, api = response_request_and_api()
    request.get.return_value = response
    if id_ and query:
        invoke(api, id_, query)
    elif id_ is None:
        invoke(api, query)
    else:
        invoke(api, id_)
    request.get.assert_called_once_with(url, params=query)
    response.json.assert_called_once_with()


def assert_succeeds_with_perform(invoke, method, url, id_=None,
                                 payload=None, **query):
    response, request, api = response_request_and_api()
    request.perform.return_value = response
    if payload:
        invoke(api, id_, payload)
    elif id_ and query:
        invoke(api, id_, query)
    elif id_ is None:
        invoke(api, query)
    else:
        invoke(api, id_)
    if payload:
        request.perform.assert_called_once_with(method, url, json=payload)
    else:
        request.perform.assert_called_once_with(method, url, params=query)
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
