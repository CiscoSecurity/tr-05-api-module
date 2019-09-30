import pytest
import six

from threatresponse.api.routing import Router
from threatresponse.exceptions import RouteError


def test_new():
    router, register = Router.new()

    assert isinstance(router, Router)
    assert callable(register)

    # Check that `register` is an instance method bound to `router`.
    self_attr = 'im_self' if six.PY2 else '__self__'
    assert getattr(register, self_attr) is router


def test_register_resolve():
    router, register = Router.new()

    def a(): pass
    def ab(): pass
    def abc(): pass

    # Check that `register` returns a function and can be used as a decorator.
    register('a')(a)
    register('a.b')(ab)
    register('a.b.c')(abc)

    with pytest.raises(RouteError):
        register('a.b')(ab)

    # Check that `router` gets populated behind the scenes.
    assert router._routes == {'a': a, 'a.b': ab, 'a.b.c': abc}

    assert router.resolve('a') is a
    assert router.resolve('a.b') is ab
    assert router.resolve('a.b.c') is abc

    with pytest.raises(RouteError):
        router.resolve('a.b.c.d')


def test_merged():
    def a_x(): pass
    def b_x(): pass
    def b_y(): pass
    def c_y(): pass

    x = Router({'a': a_x, 'b': b_x})
    y = Router({'b': b_y, 'c': c_y})

    # Check that `merged` expects instances of `Router` or at least `None`.

    with pytest.raises(TypeError):
        Router.merged(x, {})

    with pytest.raises(TypeError):
        Router.merged({}, y)

    # Check that `merged` always returns a new instance.

    z = Router.merged(x, None)
    assert z is not x and z._routes == x._routes

    z = Router.merged(None, y)
    assert z is not y and z._routes == y._routes

    # Check that `merged` preserves the resolution order.

    z = Router.merged(x, y)
    assert z._routes == {'a': a_x, 'b': b_x, 'c': c_y}

    z = Router.merged(y, x)
    assert z._routes == {'a': a_x, 'b': b_y, 'c': c_y}
