from .base_test import BaseTestCase
from threatresponse.api.base import BaseAPI


class UtilsTestCase(BaseTestCase):
    def test_absolute_url(self):
        # Testing utils function absolute_url to return correct url.

        actual = BaseAPI.absolute_url('/iroh/iroh-enrich/health')
        expect = 'https://visibility.amp.cisco.com/iroh/iroh-enrich/health'

        self.assertEqual(actual, expect)
