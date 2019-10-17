from .routing import Router
from .entity import EntityAPI


class IncidentAPI(EntityAPI):
    """https://private.intel.amp.cisco.com/index.html#/Incident"""

    __router, route = Router.new()

    def __init__(self, request):
        super(IncidentAPI, self).__init__(request, '/ctia/incident')

    @route('status')
    def _perform(self, id_, payload, response_type='json'):
        return self._post(
            '%s/%s/status' % (self._url, id_),
            json=payload,
            response_type=response_type
        )

    @route('link')
    def _perform(self, id_, payload, response_type='json'):
        return self._post(
            '%s/%s/link' % (self._url, id_),
            json=payload,
            response_type=response_type
        )

    @route('sightings.incidents')
    def _perform(self,
                 observable_type,
                 observable_value,
                 response_type='json'):
        return self._get(
            '/ctia/%s/%s/sightings/incidents' % (observable_type,
                                                 observable_value),
            response_type=response_type
        )
