from ..common import patch

from threatresponse.request.base import Request
from threatresponse.api.enrich import EnrichAPI


@patch(Request)
def test_health_api(request):
    api = EnrichAPI(request)
    api.health()

    request.post.assert_called_once_with('/iroh/iroh-enrich/health')
