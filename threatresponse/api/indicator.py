from .entity import IntelEntityAPI
from .routing import Router
from .. import urls


class IndicatorAPI(IntelEntityAPI):
    """https://private.intel.amp.cisco.com/index.html#/Indicator"""

    __router, route = Router.new()

    def __init__(self, request):
        super(IndicatorAPI, self).__init__(request, '/ctia/indicator')

    @route('judgements.indicators')
    def _perform(self, observable_type, observable_value, **kwargs):
        return self._get(
            urls.join(
                '/ctia',
                observable_value,
                observable_type,
                'judgements',
                'indicators'
            ),
            **kwargs
        )

    @route('sightings.indicators')
    def _perform(self, observable_type, observable_value, **kwargs):
        return self._get(
            urls.join(
                '/ctia',
                observable_type,
                observable_value,
                'sightings',
                'indicators'
            ),
            **kwargs
        )
