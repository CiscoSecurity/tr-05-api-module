from .entity import EntityAPI
from .routing import Router
from .. import urls


class EventAPI(EntityAPI):
    """https://private.intel.amp.cisco.com/index.html#/Event"""

    __router, route = Router.new()

    def __init__(self, request):
        super(EventAPI, self).__init__(request, '/ctia/event')

    @route('history')
    def _perform(self, id_, **kwargs):
        return self._get(
            urls.join(self._url, 'history', id_),
            **kwargs
        )
