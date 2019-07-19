import unittest
import json


class BaseTestCase(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def dict_response(self, response):
        """

        :param response: response object after request
        :return: dict from response
        """
        return json.loads(response)
