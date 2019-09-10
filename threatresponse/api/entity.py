from six.moves.urllib.parse import urljoin

from .base import API


class EntityAPI(API):

    def __init__(self, request, url):
        super(EntityAPI, self).__init__(request)

        self._url = url

    def get(self, id_, **params):
        url = urljoin(self._url, '/%s' % id_)

        response = self._request.get(url, params=params)
        response.raise_for_status()

        return response.json()

    def post(self, payload):
        response = self._request.post(self._url, json=payload)
        response.raise_for_status()

        return response.json()

    def delete(self, id_):
        url = urljoin(self._url, '/%s' % id_)

        response = self._request.delete(url)
        response.raise_for_status()

        return response.json()

    def put(self, id_, payload):
        url = urljoin(self._url, '/%s' % id_)

        response = self._request.put(url, json=payload)
        response.raise_for_status()

        return response.json()

    def external_id(self, id_, **params):
        url = urljoin(self._url, '/external_id/%s' % id_)

        response = self._request.get(url, params=params)
        response.raise_for_status()

        return response.json()

    def search(self, **params):
        url = urljoin(self._url, '/search')

        response = self._request.get(url, params=params)
        response.raise_for_status()

        return response.json()

