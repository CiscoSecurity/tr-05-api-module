from mock import MagicMock

from threatresponse.api.enrich import EnrichAPI


def test_health_api():
    request = MagicMock()
    api = EnrichAPI(request)
    api.health()

    request.post.assert_called_once_with('/iroh/iroh-enrich/health')
