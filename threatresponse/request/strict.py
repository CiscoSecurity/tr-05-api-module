import json
import requests

from .base import Request


class StrictRequest(Request):
    def __init__(self, request):
        self._request = request

    def perform(self, method, url, **kwargs):
        response = self._request.perform(method, url, **kwargs)
        extended = self._extended

        try:
            response.raise_for_status()
        except requests.HTTPError as error:
            raise extended(error)

        return response

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
