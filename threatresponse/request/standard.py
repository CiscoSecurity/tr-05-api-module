import requests

from .base import BaseRequest


class StandardRequest(BaseRequest):

    def __init__(self):
        self._session = self._create_session()

    def _create_session(self):
        # This base method can be overridden to support more elaborate behavior
        return requests.Session()

    def perform(self, method, url, **kwargs):
        return self._session.request(method, url, **kwargs)
