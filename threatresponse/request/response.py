import json

import requests


class Response(object):
    """
    Wraps an instance of the `requests.Response` class.
    Redirects all calls to get/set any attribute to inner response.
    May also customize some instance methods.
    """

    def __init__(self, response):
        self._response = response

    def __getattr__(self, key):
        return getattr(self._response, key)

    def __setattr__(self, key, value):
        # Antidote against infinite recursion.
        if key == '_response':
            super(Response, self).__setattr__(key, value)
        else:
            setattr(self._response, key, value)

    def raise_for_status(self):
        extended = self._extended

        try:
            self._response.raise_for_status()
        except requests.HTTPError as error:
            raise extended(error)

    @staticmethod
    def _extended(error):
        # Try to extend the default error message with the response payload
        # in order to give the user more insight about what went wrong.

        try:
            payload = error.response.json()
        except json.JSONDecodeError:
            return error

        message = error.args[0]  # 1-element tuple.
        message += '\n' + json.dumps(payload, indent=4)

        error.args = (message,)

        return error
