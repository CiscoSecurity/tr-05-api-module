from six.moves.urllib.parse import urljoin


class BaseAPI(object):
    BASE_URL = 'https://visibility.amp.cisco.com'

    def __init__(self, request):
        self._request = request

    @classmethod
    def build_full_url(cls, endpoint_path_template, *args, **kwargs):
        endpoint_path = endpoint_path_template.format(*args, **kwargs)
        return urljoin(cls.BASE_URL, endpoint_path)
