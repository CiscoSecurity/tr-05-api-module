from .entity import EntityAPI
from .routing import Router


class SightingAPI(EntityAPI):
    """https://private.intel.amp.cisco.com/index.html#/Sighting"""

    __router, route = Router.new()

    def __init__(self, request):
        super(SightingAPI, self).__init__(request, '/ctia/sighting')

    @route('sightings')
    def _perform(self, observable_type, observable_value):
        return self._get(
            '/ctia/%s/%s/sightings' %
            (observable_type, observable_value)
        )
