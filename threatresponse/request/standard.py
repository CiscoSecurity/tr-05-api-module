import requests

from .base import Request


class StandardRequest(Request):
    """
    Performs plain HTTP requests using the `requests` library.
    """

    def __init__(self):
        self._session = requests.Session()

    def perform(self, method, url, **kwargs):
        return self._session.request(method, url, **kwargs)
