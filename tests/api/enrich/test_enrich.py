from mock import MagicMock

from threatresponse.api.enrich import (
    EnrichAPI,
    DeliberateAPI,
    ObserveAPI,
    ReferAPI,
)


def test_types_of_inner_apis():
    request = MagicMock()

    api = EnrichAPI(request)

    assert isinstance(api.deliberate, DeliberateAPI)
    assert isinstance(api.observe, ObserveAPI)
    assert isinstance(api.refer, ReferAPI)


def test_health():
    request = MagicMock()

    api = EnrichAPI(request)
    api.health()

    request.post.assert_called_once_with('/iroh/iroh-enrich/health')
