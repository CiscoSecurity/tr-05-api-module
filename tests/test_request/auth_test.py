from threatresponse import ThreatResponse
from tests.base_test import BaseTestCase
from requests.exceptions import HTTPError
import mock


class AuthTestCase(BaseTestCase):
    @mock.patch('requests.Session.request')
    def test_create_instance_with_invalid_credentials(self, request_mock):
        # Testing creation of ThreatResponse instance with invalid credentials.
        # Should throw error with explanation.

        response_mock = mock.MagicMock()

        def raise_for_status():
            raise HTTPError(
                'Mocked error message',
                request=request_mock,
                response=response_mock,
            )

        response_mock.raise_for_status.side_effect = raise_for_status
        response_mock.json.return_value = {'foo': 'bar'}

        request_mock.return_value = response_mock

        with self.assertRaises(HTTPError):
            ThreatResponse(
                client_id='y',
                client_password='x',
            )

        request_mock.assert_called_once_with(
            'POST',
            'https://visibility.amp.cisco.com/iroh/oauth2/token',
            auth=('y', 'x'),
            data={'grant_type': 'client_credentials'},
            headers={'Content-Type': 'application/x-www-form-urlencoded',
                     'Accept': 'application/json'},
        )
