from six.moves.urllib.parse import urljoin


class BaseAPI(object):
    BASE_URL = 'https://visibility.amp.cisco.com'

    def __init__(self, request):
        self._request = request

    def _get(self, endpoint, payload=None):
        return self._perform('get', endpoint, payload)

    def _post(self, endpoint, payload=None):
        return self._perform('post', endpoint, payload)

    def _perform(self, method, endpoint, payload=None):
        url = self.absolute_url(endpoint)

        return (
            self._request.perform(method, url, json=payload) if payload else
            self._request.perform(method, url)
        ).json()

    @classmethod
    def absolute_url(cls, endpoint):
        return urljoin(cls.BASE_URL, endpoint)
