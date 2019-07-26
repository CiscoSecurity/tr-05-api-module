from unittest import TestCase
from mock import patch


# TODO.
class StrictTestCase(TestCase):

    @patch('threatresponse.request.base.Request')
    def test(self, mock):
        pass
