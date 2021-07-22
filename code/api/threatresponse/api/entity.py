from .base import API
from .. import urls
from ..exceptions import ResponseTypeError


class EntityAPI(API):

    def __init__(self, request, url):
        super(EntityAPI, self).__init__(request)

        self._url = url

    def get(self, id_=None, **kwargs):
        if id_:
            url = urls.join(self._url, id_)
        else:
            url = self._url

        return self._get(url, **kwargs)

    def post(self, payload, **kwargs):
        return self._post(self._url, json=payload, **kwargs)

    def put(self, id_, payload, **kwargs):
        return self._put(
            urls.join(self._url, id_),
            json=payload,
            **kwargs
        )

    def patch(self, id_, payload, **kwargs):
        return self._patch(
            urls.join(self._url, id_),
            json=payload,
            **kwargs
        )

    def delete(self, id_, **kwargs):
        if 'response_type' in kwargs:
            raise ResponseTypeError("'response_type' cannot be "
                                    "specified for this method.")

        return self._delete(
            urls.join(self._url, id_),
            response_type='raw',
            **kwargs
        )


class Search(EntityAPI):
    NAME = 'search'

    def get(self, **kwargs):
        return self._get(
            urls.join(self._url, self.NAME),
            **kwargs
        )

    def delete(self, **kwargs):
        return self._delete(
            urls.join(self._url, self.NAME),
            **kwargs
        )

    def count(self, **kwargs):
        return self._get(
            urls.join(self._url, self.NAME, 'count'),
            **kwargs
        )


class Metric(EntityAPI):
    NAME = 'metric'

    def histogram(self, **kwargs):
        return self._get(
            urls.join(self._url, self.NAME, 'histogram'),
            **kwargs
        )

    def topn(self, **kwargs):
        return self._get(
            urls.join(self._url, self.NAME, 'topn'),
            **kwargs
        )

    def cardinality(self, **kwargs):
        return self._get(
            urls.join(self._url, self.NAME, 'cardinality'),
            **kwargs
        )


class IntelEntityAPI(EntityAPI):

    def __init__(self, request, url):
        super(IntelEntityAPI, self).__init__(request, url)
        self.search = Search(request, url)
        self.metric = Metric(request, url)

    def external_id(self, id_, **kwargs):
        return self._get(
            urls.join(self._url, 'external_id', id_),
            **kwargs
        )
