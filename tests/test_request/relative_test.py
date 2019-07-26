from mock import patch

from tests.base_test import BaseTestCase
from threatresponse.request.relative import RelativeRequest


class RelativeTestCase(BaseTestCase):

    @patch('threatresponse.request.base.Request')
    def test_that_relative_request_builds_correct_parameters(self, mock):
        mock.perform.side_effect = lambda *args, **kwargs: None

        request = RelativeRequest(mock, 'http://one.com')
        request.post('/two', json={'some': 'data'})

        mock.perform.assert_called_once_with('POST', 'http://one.com/two', json={'some': 'data'})

    @patch('threatresponse.request.base.Request')
    def test_that_relative_request_returns_correct_response(self, mock):
        mock.perform.side_effect = lambda *args, **kwargs: 'duck'

        request = RelativeRequest(mock, 'http://one.com')
        response = request.post('/two')

        self.assertEqual(response, 'duck')
