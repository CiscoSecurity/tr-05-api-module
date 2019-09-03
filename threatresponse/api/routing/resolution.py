class Resolution(object):
    """ Represents a resolution of attribute chains.
    `resolution.x.y.z` would contain `resolution._route = ['x', 'y', 'z']`.
    """

    def __init__(self, owner, routes, route=None):
        self._owner = owner
        self._route = route or []
        self._routes = routes

    def __call__(self, *args, **kwargs):
        """ Invokes a method by the built route. """

        route = '.'.join(self._route)
        method = self._routes.resolve(route)

        return method(self._owner, *args, **kwargs)

    def __getattr__(self, item):
        return Resolution(self._owner, self._routes, self._route + [item])

    def merge(self, routes):
        """ Merges `Routes` into inner `Routes`. """

        self._routes.merge(routes)
