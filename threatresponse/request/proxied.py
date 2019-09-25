from .standard import StandardRequest


class ProxiedRequest(StandardRequest):
    """
    Supports request proxying via a specified proxy server.
    """

    def __init__(self, proxy):
        super(ProxiedRequest, self).__init__()

        self._session.proxies = {'http': proxy, 'https': proxy}
