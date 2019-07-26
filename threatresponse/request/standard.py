import requests

from .base import Request


class StandardRequest(Request):

    def __init__(self):
        self._session = requests.Session()

    def perform(self, method, url, **kwargs):
        return self._session.request(method, url, **kwargs)
