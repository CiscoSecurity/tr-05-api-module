class Pipe(object):
    """ A composition of many functions. """

    def __init__(self, head, *tail):
        self._head = head
        self._tail = tail

    def __call__(self, *args):
        result = self._head(*args)

        for command in self._tail:
            result = command(result)

        return result


class CachedPipe(object):

    def __init__(self, pipe):
        self._pipe = pipe
        self._cache = {}

    def __call__(self, *args):
        if args in self._cache:
            result = self._cache[args]
        else:
            result = self._pipe(*args)

            self._cache[args] = result

        return result
