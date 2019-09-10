from .entity import EntityAPI
from .base import API


class IntelAPI(API):

    def __init__(self, request):
        super(IntelAPI, self).__init__(request)

        self._actor = EntityAPI(request, '/ctia/actor/')
        self._actor.__doc__ = \
            "https://private.intel.amp.cisco.com/index.html#!/Actor/"

    @property
    def actor(self):
        return self._actor
