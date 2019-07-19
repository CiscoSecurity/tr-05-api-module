from .base_test import BaseTestCase
from threatresponse import ThreatResponse
import requests


class AuthTestCase(BaseTestCase):

    def test_try_to_create_instance_with_invalid_credentials(self):
        # Testing creation of ThreatResponse instance with invalid credentials.
        # Should throw error with explanation

        try:
            ThreatResponse(
                client_id='1231',
                client_password='ssZi617xy1O-sf_Jlcw',
            )
        except Exception as e:
            self.assertEqual({'error_uri': 'https://tools.ietf.org/html/rfc6749#section-5.2',
                              'error_description': 'unknown client',
                              'error': 'invalid_client'},
                                        e.response.json())


