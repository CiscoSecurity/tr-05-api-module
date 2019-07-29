from unittest import TestCase
from mock import patch, MagicMock

from threatresponse.api.enrich.refer import ReferAPI


class ReferTestCase(TestCase):

    @patch('threatresponse.request.base.Request')
    def test_observables(self, request):
        payload = [
            {"value": "string",
             "type": "file_path"}
        ]
        request.post.side_effect = lambda *args, **kwargs: MagicMock()

        api = ReferAPI(request)
        api.observables(payload)

        request.post.assert_called_once_with('/iroh/iroh-enrich/refer/observables', json=payload)

    @patch('threatresponse.request.base.Request')
    def test_sighting(self, request):
        payload = {'hello': 'world'}
        request.post.side_effect = lambda *args, **kwargs: MagicMock()

        api = ReferAPI(request)
        api.sighting(payload)

        request.post.assert_called_once_with('/iroh/iroh-enrich/refer/sighting', json=payload)

    @patch('threatresponse.request.base.Request')
    def test_sighting_ref(self, request):
        payload = 'hello world'
        request.post.side_effect = lambda *args, **kwargs: MagicMock()

        api = ReferAPI(request)
        api.sighting_ref(payload)

        request.post.assert_called_once_with('/iroh/iroh-enrich/refer/sighting_ref', json=payload)
