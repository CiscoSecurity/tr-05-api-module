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

        return self._get(url, params=params)

    def post(self, payload, **params):
        return self._post(self._url, json=payload, params=params)

    def put(self, id_, payload):
        return self._put('%s/%s' % (self._url, id_), json=payload)

    def patch(self, id_, payload):
        return self._patch('%s/%s' % (self._url, id_), json=payload)

    def delete(self, id_):
        self._delete('%s/%s' % (self._url, id_), response='raw')

    def search(self, **params):
        return self._get('%s/search' % self._url, params=params)

    def external_id(self, id_, **params):
        return self._get(
            '%s/external_id/%s' % (self._url, id_),
            params=params
        )
