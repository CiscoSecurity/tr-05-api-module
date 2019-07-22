from .base_test import BaseTestCase
from threatresponse import ThreatResponse


class AuthTestCase(BaseTestCase):
    def test_create_instance_with_invalid_credentials(self):
        # Testing creation of ThreatResponse instance with invalid credentials.
        # Should throw error with explanation.

        with self.assertRaises(Exception) as context:
            ThreatResponse('x', 'y')

        actual = context.exception.response.json()
        expect = {
            'error_uri': 'https://tools.ietf.org/html/rfc6749#section-5.2',
            'error_description': 'unknown client',
            'error': 'invalid_client'
        }

        self.assertEqual(actual, expect)
