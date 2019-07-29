from unittest import TestCase

from threatresponse.api.enrich.observe import ObserveAPI
from threatresponse.request.base import Request
from ...common import patch


class ObserveTestCase(TestCase):

    @patch(Request)
    def test_observables(self, request):
        payload = [{'foo': 'bar'}]

        api = ObserveAPI(request)
        api.observables(payload)

        request.post.assert_called_once_with(
            '/iroh/iroh-enrich/observe/observables', json=payload)

    @patch(Request)
    def test_sighting(self, request):
        payload = {'foo': 'bar'}

        api = ObserveAPI(request)
        api.sighting(payload)

        request.post.assert_called_once_with(
            '/iroh/iroh-enrich/observe/sighting', json=payload)

    @patch(Request)
    def test_sighting_ref(self, request):
        payload = 'foo'

        api = ObserveAPI(request)
        api.sighting_ref(payload)

        request.post.assert_called_once_with(
            '/iroh/iroh-enrich/observe/sighting_ref', json=payload)
