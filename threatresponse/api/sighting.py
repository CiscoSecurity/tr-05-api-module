from .entity import IntelEntityAPI
from .routing import Router
from .. import urls


class SightingAPI(IntelEntityAPI):
    """https://private.intel.amp.cisco.com/index.html#/Sighting"""

    __router, route = Router.new()

    def __init__(self, request):
        super(SightingAPI, self).__init__(request, '/ctia/sighting')

    @route('sightings')
    def _perform(self, observable_type, observable_value, **kwargs):
        return self._get(
            urls.join('/ctia', observable_type, observable_value, 'sightings'),
            **kwargs
        )
