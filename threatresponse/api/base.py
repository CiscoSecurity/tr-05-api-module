from .routing import Resolution, Router


class API(object):
    """ Base `API`. """

    def __init__(self, request):
        self._request = request
        self._resolution = None

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
