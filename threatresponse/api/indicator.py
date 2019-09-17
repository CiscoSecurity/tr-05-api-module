from .routing import Router
from .entity import EntityAPI


class IndicatorAPI(EntityAPI):
    """https://private.intel.amp.cisco.com/index.html#/Indicator"""

    __router, route = Router.new()

    def __init__(self, request):
        super(IndicatorAPI, self).__init__(request, '/ctia/indicator')

    @route('judgements.indicators')
    def _perform(self, observable_type, observable_value):
        return self._get(
            '/ctia/%s/%s/judgements/indicators' %
            (observable_type, observable_value)
        )

    @route('sightings.indicators')
    def _perform(self, observable_type, observable_value):
        return self._get(
            '/ctia/%s/%s/sightings/indicators' %
            (observable_type, observable_value)
        )
