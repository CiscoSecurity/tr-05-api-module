from six.moves.urllib.parse import urljoin

from .base import Request


class RelativeRequest(Request):
    """
    Performs requests relative to provided `prefix`.
    """

    def __init__(self, request, prefix):
        self._request = request
        self._prefix = prefix

    def perform(self, method, url, **kwargs):
        url = urljoin(self._prefix, url)

        return self._request.perform(method, url, **kwargs)
