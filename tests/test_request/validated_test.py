from unittest import TestCase
from mock import patch


# TODO.
class ValidatedTestCase(TestCase):

    @patch('threatresponse.request.base.Request')
    def test(self, mock):
        pass
