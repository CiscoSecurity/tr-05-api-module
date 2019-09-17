from .routing import Resolution, Router


class API(object):
    """ Base `API`. """

    def __init__(self, request):
        self._request = request
        self._resolution = None

    def _get(self, *args, **kwargs):
        return self.__perform('GET', *args, **kwargs)

    def _post(self, *args, **kwargs):
        return self.__perform('POST', *args, **kwargs)

    def _put(self, *args, **kwargs):
        return self.__perform('PUT', *args, **kwargs)

    def _patch(self, *args, **kwargs):
        return self.__perform('PATCH', *args, **kwargs)

    def _delete(self, *args, **kwargs):
        return self.__perform('DELETE', *args, **kwargs)

    def __perform(self, url, *args, **kwargs):
        response = self._request.perform(url, *args, **kwargs)
        response.raise_for_status()

        return response.json()

    def __getattr__(self, item):
        if self._resolution is None:
            self._resolution = self._build_resolution()

        return self._resolution.__getattr__(item)

    def _build_resolution(self):
        """ Traverses the MRO and merges values of
        `__router` attributes to build a single `Resolution`. """

        router = None

        for cls in type(self).mro():
            attribute = '_{}__{}'.format(cls.__name__, 'router')

            if hasattr(cls, attribute):
                router = Router.merged(router, getattr(cls, attribute))

        if router is None:
            raise Exception(
                'Could not build a resolution for {}.'.format(type(self))
            )

        return Resolution(self, router)
