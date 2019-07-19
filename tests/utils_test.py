from .base_test import BaseTestCase
from threatresponse.api.base import BaseAPI


class UtilsTestCase(BaseTestCase):

    def test_build_full_url(self):
        #Testing utils function absolute_url to return correct url

        self.assertEqual(BaseAPI.absolute_url('/iroh/iroh-enrich/health'), 'https://visibility.amp.cisco.com/iroh/iroh-enrich/health')