from .base import API


class EntityAPI(API):

    def __init__(self, request, url):
        super(EntityAPI, self).__init__(request)

        self._url = url

    def get(self, id_=None, response_type='json', **params):
        if id_:
            url = '%s/%s' % (self._url, id_)
        else:
            url = self._url

        return self._get(
            url,
            params=params,
            response_type=response_type
        )

    def post(self, payload, response_type='json',  **params):
        return self._post(
            self._url,
            json=payload,
            params=params,
            response_type=response_type
        )

    def put(self, id_, payload, response_type='json'):
        return self._put(
            '%s/%s' % (self._url, id_),
            json=payload,
            response_type=response_type
        )

    def patch(self, id_, payload, response_type='json'):
        return self._patch(
            '%s/%s' % (self._url, id_),
            json=payload,
            response_type=response_type
        )

    def delete(self, id_):
        self._delete(
            '%s/%s' % (self._url, id_),
            response_type='raw'
        )

    def search(self, response_type='json', **params):
        return self._get(
            '%s/search' % self._url,
            params=params,
            response_type=response_type
        )

    def external_id(self, id_, response_type='json', **params):
        return self._get(
            '%s/external_id/%s' % (self._url, id_),
            params=params,
            response_type=response_type
        )
