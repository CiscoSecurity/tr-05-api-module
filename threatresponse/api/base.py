from .routing import Resolution, Router
from ..exceptions import ResponseTypeError


class API(object):
    """ Base `API`. """

    def __init__(self, request):
        self._request = request
        self._resolution = None

    def _get(self, *args, **kwargs):
        return self.__perform('GET', *args, **kwargs)

    def _post(self, *args, **kwargs):
        return self.__perform('POST', *args, **kwargs)

    def _put(self, *args, **kwargs):
        return self.__perform('PUT', *args, **kwargs)

    def _patch(self, *args, **kwargs):
        return self.__perform('PATCH', *args, **kwargs)

    def _delete(self, *args, **kwargs):
        return self.__perform('DELETE', *args, **kwargs)

    def __perform(self, method, *args, **kwargs):
        response_types = {
            'raw': lambda response: response,
            'json': lambda response: response.json(),
            'text': lambda response: response.text,
        }
        response_type = kwargs.pop('response_type', 'json')

        if response_type not in response_types:
            raise ResponseTypeError(
                'Unsupported response type {type}, must be one of:'
                ' {types}.'.format(
                    type=repr(response_type),
                    types=', '.join(map(repr, response_types.keys())),
                )
            )

        response = self._request.perform(method, *args, **kwargs)
        response.raise_for_status()

        processed = response_types[response_type]

        return processed(response)

    def __getattr__(self, item):
        if self._resolution is None:
            self._resolution = self._build_resolution()

        return self._resolution.__getattr__(item)

    def _build_resolution(self):
        """ Traverses the MRO and merges values of
        `__router` attributes to build a single `Resolution`. """

        router = None

        for cls in type(self).mro():
            attribute = '_{class_name}__{router}'.format(
                class_name=cls.__name__,
                router='router'
            )

            if hasattr(cls, attribute):
                router = Router.merged(router, getattr(cls, attribute))

        if router is None:
            raise Exception(
                'Could not build a resolution for {type}.'.format(
                    type=type(self)
                )
            )

        return Resolution(self, router)
