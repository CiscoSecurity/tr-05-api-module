from mock import MagicMock

from threatresponse.api.routing import Resolution


def test_getattr():
    owner = object()
    router = object()

    def check(resolution, route):
        assert (
            isinstance(resolution, Resolution) and (
                resolution._owner is owner) and (
                resolution._router is router) and (
                resolution._route == route)
        )

    resolution = Resolution(owner, router)

    check(resolution, [])
    check(resolution.x, ['x'])
    check(resolution.x.y, ['x', 'y'])
    check(resolution.x.y.z, ['x', 'y', 'z'])


def test_call():
    owner = object()
    router = MagicMock()

    method = MagicMock()
    router.resolve.return_value = method

    resolution = Resolution(owner, router, ['alpha', 'beta', 'gamma'])

    resolution('a', 'b', 'c', x=1, y=2, z=3)

    router.resolve.assert_called_once_with('alpha.beta.gamma')

    method.assert_called_once_with(owner, 'a', 'b', 'c', x=1, y=2, z=3)
