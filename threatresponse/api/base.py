from .routing import Resolution, Routes


class API(object):
    """ Base `API`. """

    def __init__(self, request):
        self._request = request

    def __getattr__(self, item):
        resolution = self._resolution()

        if resolution is None:
            raise Exception(
                "Couldn't build a resolution for {}.".format(type(self))
            )

        return resolution.__getattr__(item)

    def _resolution(self):
        """ Traverses the MRO and merges `__routes` attributes
        to build a single `Resolution`. """

        resolution = None

        for x in type(self).mro():
            attribute = '_{}__{}'.format(x.__name__, 'routes')

            if hasattr(x, attribute):
                if resolution is None:
                    resolution = Resolution(self, getattr(x, attribute))
                else:
                    resolution.merge(getattr(x, attribute))

        return resolution

    @staticmethod
    def routes():
        """ Returns a tuple of `(routes, routes.register)`.
        Usage example:
            class SomeAPI(API):
                __routes, route = API.routes()

                @route('a.b.c')
                def _perform(self, ...):
                    ...
        """

        routes = Routes()

        return routes, routes.register
