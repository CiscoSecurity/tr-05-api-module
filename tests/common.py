import mock


def patch(cls):
    path = '{}.{}'.format(cls.__module__, cls.__name__)

    return mock.patch(path)
