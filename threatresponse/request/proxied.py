from .standard import StandardRequest


class ProxiedRequest(StandardRequest):
    """
    Supports HTTP request proxying via a specified proxy server.
    """

    def __init__(self, proxy):
        super(ProxiedRequest, self).__init__()

        self._proxy = proxy

        self._configure_session_proxies()

    def _configure_session_proxies(self):
        self._session.proxies = {
            'http': self._proxy,
            'https': self._proxy,
        }
