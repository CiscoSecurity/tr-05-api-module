from unittest import TestCase
from mock import MagicMock

from tests.common import patch

from threatresponse.request.base import Request
from threatresponse.api.enrich import EnrichAPI


class EnrichTestCase(TestCase):

    @patch(Request)
    def test_health_api(self, request):
        request.post.side_effect = lambda *args, **kwargs: MagicMock()

        api = EnrichAPI(request)
        api.health()

        request.post.assert_called_once_with('/iroh/iroh-enrich/health')
