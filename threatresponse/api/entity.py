from six.moves.urllib.parse import quote

from .base import API
from ..exceptions import ResponseTypeError


class EntityAPI(API):

    def __init__(self, request, url):
        super(EntityAPI, self).__init__(request)

        self._url = url

    def get(self, id_=None, **kwargs):
        if id_:
            url = '%s/%s' % (self._url, quote(id_))
        else:
            url = self._url

        return self._get(url, **kwargs)

    def post(self, payload, **kwargs):
        return self._post(self._url, json=payload, **kwargs)

    def put(self, id_, payload, **kwargs):
        return self._put(
            '%s/%s' % (self._url, quote(id_)),
            json=payload,
            **kwargs
        )

    def patch(self, id_, payload, **kwargs):
        return self._patch(
            '%s/%s' % (self._url, quote(id_)),
            json=payload,
            **kwargs
        )

    def delete(self, id_, **kwargs):
        if 'response_type' in kwargs:
            raise ResponseTypeError("'response_type' cannot be "
                                    "specified for this method.")

        return self._delete(
            '%s/%s' % (self._url, quote(id_)),
            response_type='raw',
            **kwargs
        )

    def search(self, **kwargs):
        return self._get(
            '%s/search' % self._url,
            **kwargs
        )

    def external_id(self, id_, **kwargs):
        return self._get(
            '%s/external_id/%s' % (self._url, quote(id_)),
            **kwargs
        )
