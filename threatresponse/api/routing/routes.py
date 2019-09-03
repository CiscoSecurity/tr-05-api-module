class Routes(object):
    """ Represents a mapping from a route to a method. """

    def __init__(self, routes=None):
        self._routes = routes or {}

    def register(self, route):
        """ Returns a function to register a method by a specified `route`. """

        def registration(method):
            if route in self._routes:
                raise ValueError(
                    "Route '{}' has already been registered.".format(route)
                )

            self._routes[route] = method

        return registration

    def resolve(self, route):
        """ Returns a method by the specified route. """

        if not route:
            raise ValueError("Route cannot be empty.")
        if route not in self._routes:
            raise ValueError("Route '{}' is not registered.".format(route))

        return self._routes[route]

    def merge(self, other):
        """ Merges another instance of `Routes` into the current one. """

        if not isinstance(other, Routes):
            raise TypeError(
                'Expected an argument '
                'of {}, but got {}.'.format(Routes, type(other))
            )

        for key in other._routes:
            if key not in self._routes:
                self._routes[key] = other._routes[key]

    @classmethod
    def new(cls):
        """ Returns a tuple of `(obj, obj.register)`. """

        obj = cls()
        return obj, obj.register
