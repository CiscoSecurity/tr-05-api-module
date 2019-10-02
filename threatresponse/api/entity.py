from .base import API


class EntityAPI(API):

    def __init__(self, request, url):
        super(EntityAPI, self).__init__(request)

        self._url = url

    def get(self, id_=None, **params):
        if id_:
            url = '%s/%s' % (self._url, id_)
        else:
            url = self._url
        response = self._request.get(url, params=params)
        response.raise_for_status()

        return response.json()

    def post(self, payload, **params):
        response = self._request.post(self._url, json=payload, params=params)
        response.raise_for_status()

        return response.json()

    def delete(self, id_):
        url = '%s/%s' % (self._url, id_)

        response = self._request.delete(url)
        response.raise_for_status()

    def put(self, id_, payload):
        url = '%s/%s' % (self._url, id_)

        response = self._request.put(url, json=payload)
        response.raise_for_status()

        return response.json()

    def patch(self, id_, payload):
        url = '%s/%s' % (self._url, id_)

        response = self._request.patch(url, json=payload)
        response.raise_for_status()

        return response.json()

    def external_id(self, id_, **params):
        url = '%s/external_id/%s' % (self._url, id_)

        response = self._request.get(url, params=params)
        response.raise_for_status()

        return response.json()

    def search(self, **params):
        url = '%s/search' % self._url

        response = self._request.get(url, params=params)
        response.raise_for_status()

        return response.json()
