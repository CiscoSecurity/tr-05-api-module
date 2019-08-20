import pytest
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


def test_health_succeeds():
    response = MagicMock()

    request = MagicMock()
    request.post.return_value = response

    api = EnrichAPI(request)
    api.health()

    request.post.assert_called_once_with('/iroh/iroh-enrich/health')

    response.json.assert_called_once_with()


def test_health_fails():
    class TestError(Exception):
        pass

    response = MagicMock()
    response.raise_for_status.side_effect = TestError('Oops!')

    request = MagicMock()
    request.post.return_value = response

    api = EnrichAPI(request)
    with pytest.raises(TestError):
        api.health()

    request.post.assert_called_once_with('/iroh/iroh-enrich/health')

    response.raise_for_status.assert_called_once_with()
