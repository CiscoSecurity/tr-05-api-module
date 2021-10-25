from .entity import IntelEntityAPI
from .routing import Router
from .. import urls


class IncidentAPI(IntelEntityAPI):
    """https://private.intel.amp.cisco.com/index.html#/Incident"""

    __router, route = Router.new()

    def __init__(self, request):
        super(IncidentAPI, self).__init__(request, '/ctia/incident')

    @route('status')
    def _perform(self, id_, payload, **kwargs):
        return self._post(
            urls.join(self._url, id_, 'status'),
            json=payload,
            **kwargs
        )

    @route('link')
    def _perform(self, id_, payload, **kwargs):
        return self._post(
            urls.join(self._url, id_, 'link'),
            json=payload,
            **kwargs
        )

    @route('sightings.incidents')
    def _perform(self, observable_type, observable_value, **kwargs):
        return self._get(
            urls.join(
                '/ctia',
                observable_type,
                observable_value,
                'sightings',
                'incidents'
            ),
            **kwargs
        )
