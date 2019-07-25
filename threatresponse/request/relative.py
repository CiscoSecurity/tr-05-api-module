from six.moves.urllib.parse import urljoin

from .base import Request


class RelativeRequest(Request):
    def __init__(self, inner, path):
        self._request = inner
        self._path = path

    def perform(self, method, url, **kwargs):
        url = urljoin(self._path, url)

        return self._request.perform(method, url, **kwargs)
