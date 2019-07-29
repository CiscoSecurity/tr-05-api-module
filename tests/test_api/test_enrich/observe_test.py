from unittest import TestCase
from mock import patch, MagicMock

from threatresponse.api.enrich.observe import ObserveAPI


class ObserveTestCase(TestCase):

    @patch('threatresponse.request.base.Request')
    def test_observables(self, request):
        payload = [{'foo': 'bar'}]
        request.post.side_effect = lambda *args, **kwargs: MagicMock()

        api = ObserveAPI(request)
        api.observables(payload)

        request.post.assert_called_once_with(
            '/iroh/iroh-enrich/observe/observables', json=payload)

    @patch('threatresponse.request.base.Request')
    def test_sighting(self, request):
        payload = {'foo': 'bar'}
        request.post.side_effect = lambda *args, **kwargs: MagicMock()

        api = ObserveAPI(request)
        api.sighting(payload)

        request.post.assert_called_once_with(
            '/iroh/iroh-enrich/observe/sighting', json=payload)

    @patch('threatresponse.request.base.Request')
    def test_sighting_ref(self, request):
        payload = 'foo'
        request.post.side_effect = lambda *args, **kwargs: MagicMock()

        api = ObserveAPI(request)
        api.sighting_ref(payload)

        request.post.assert_called_once_with(
            '/iroh/iroh-enrich/observe/sighting_ref', json=payload)
