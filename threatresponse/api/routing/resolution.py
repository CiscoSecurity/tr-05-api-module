class Resolution(object):
    """ Represents a resolution of attribute chains.
    `resolution.x.y.z` would contain `resolution._route = ['x', 'y', 'z']`.
    """

    def __init__(self, owner, router, route=None):
        self._owner = owner
        self._router = router
        self._route = route or []

    def __call__(self, *args, **kwargs):
        """ Invokes a method by the built route. """

        route = '.'.join(self._route)
        method = self._router.resolve(route)

        return method(self._owner, *args, **kwargs)

    def __getattr__(self, item):
        return Resolution(self._owner, self._router, self._route + [item])
