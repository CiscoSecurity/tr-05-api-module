from itertools import chain

from ...exceptions import RouteError


class Router(object):
    """ Represents a mapping from a route to a method. """

    def __init__(self, routes=None):
        self._routes = routes or {}

    def register(self, route):
        """ Returns a function to register a method by a specified `route`. """

        def register(method):
            if route in self._routes:
                raise RouteError(
                    'Route {} has already been registered.'.format(repr(route))
                )

            self._routes[route] = method

            # We do not return anything
            # to set the decorated method to `None`.
            return None

        return register

    def resolve(self, route):
        """ Returns a method by the specified route. """

        if not route:
            raise RouteError('Route cannot be empty.')
        if route not in self._routes:
            raise RouteError('Route {} is not registered.'.format(repr(route)))

        return self._routes[route]

    @staticmethod
    def merged(x, y):
        """ Merges two instances of `Router` into a single one. """

        message = 'Expected {} to be of type {}, but got {}.'

        if x is not None and not isinstance(x, Router):
            raise TypeError(message.format(repr('x'), Router, type(x)))
        if y is not None and not isinstance(y, Router):
            raise TypeError(message.format(repr('y'), Router, type(y)))

        x = x._routes if x is not None else {}
        y = y._routes if y is not None else {}

        result = {}

        for key, value in chain(x.items(), y.items()):
            if key not in result:
                result[key] = value

        return Router(result)

    @staticmethod
    def new():
        """ Returns a tuple of `(router, router.register)`.

        Usage example:
            class SomeAPI(API):
                __router, route = Router.new()

                @route('a.b.c')
                def _perform(self, ...):
                    ...
        """

        router = Router()

        return router, router.register
