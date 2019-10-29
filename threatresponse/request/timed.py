from .base import Request


class TimedRequest(Request):
    """
    Sets the default request timeout (unless explicitly specified).
    """

    def __init__(self, request, timeout):
        self._request = request
        self._timeout = timeout

    def perform(self, method, url, **kwargs):
        kwargs.setdefault('timeout', self._timeout)

        return self._request.perform(method, url, **kwargs)
