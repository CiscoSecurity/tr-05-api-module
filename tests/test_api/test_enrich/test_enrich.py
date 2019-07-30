from mock import MagicMock

from threatresponse.api.enrich import (
    EnrichAPI,
    DeliberateAPI,
    ObserveAPI,
)


def test_composite_structure():
    request = MagicMock()

    api = EnrichAPI(request)

    assert isinstance(api.deliberate, DeliberateAPI)
    assert isinstance(api.observe, ObserveAPI)


def test_health():
    request = MagicMock()

    api = EnrichAPI(request)
    api.health()

    request.post.assert_called_once_with('/iroh/iroh-enrich/health')
