from mock import MagicMock

from threatresponse.api import IntelAPI


def test_event_without_id_succeeds():
    assert_succeeds_with_get(
        lambda api, id_: api.feedback.get(),
        url='/ctia/feedback',
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


def response_request_and_api():
    response = MagicMock()
    request = MagicMock()
    api = IntelAPI(request)

    return response, request, api
