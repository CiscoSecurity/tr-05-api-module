from six.moves.urllib.parse import urljoin


class BaseAPI(object):
    BASE_URL = 'https://visibility.amp.cisco.com'

    def __init__(self, request):
        self._request = request

    @classmethod
    def absolute_url(cls, endpoint):
        return urljoin(cls.BASE_URL, endpoint)
