from unittest import TestCase

from tests.common import patch
from threatresponse.request.base import Request
from threatresponse.api.enrich.refer import ReferAPI


class ReferTestCase(TestCase):

    @patch(Request)
    def test_observables(self, request):
        payload = [
            {"value": "string",
             "type": "file_path"}
        ]

        api = ReferAPI(request)
        api.observables(payload)

        request.post.assert_called_once_with('/iroh/iroh-enrich/refer/observables', json=payload)

    @patch(Request)
    def test_sighting(self, request):
        payload = {'hello': 'world'}

        api = ReferAPI(request)
        api.sighting(payload)

        request.post.assert_called_once_with('/iroh/iroh-enrich/refer/sighting', json=payload)

    @patch(Request)
    def test_sighting_ref(self, request):
        payload = 'hello world'

        api = ReferAPI(request)
        api.sighting_ref(payload)

        request.post.assert_called_once_with('/iroh/iroh-enrich/refer/sighting_ref', json=payload)
