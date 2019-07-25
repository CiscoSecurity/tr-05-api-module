from threatresponse import ThreatResponse
from tests.base_test import BaseTestCase
import mock as mock


class EnrichTestCase(BaseTestCase):
    @mock.patch('requests.Session.request')
    def test_health_api(self, request_mock):
        # Test call to health API.

        tr = ThreatResponse(client_id='y', client_password='x')
        call = tr.enrich.health()
        self.assertEqual(request_mock.call_args_list[-1].args, ('POST', 'https://visibility.amp.cisco.com/iroh/iroh-enrich/health'))
        # TODO: Mock _request_token method and add check for token.
        # self.assertEqual(request_mock.call_args_list[-1].kwargs, {'Authorization': "Bearer token"})
