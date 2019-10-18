from six.moves.urllib.parse import quote

from .routing import Router
from .entity import EntityAPI


class IncidentAPI(EntityAPI):
    """https://private.intel.amp.cisco.com/index.html#/Incident"""

    __router, route = Router.new()

    def __init__(self, request):
        super(IncidentAPI, self).__init__(request, '/ctia/incident')

    @route('status')
    def _perform(self, id_, payload, **kwargs):
        return self._post(
            '%s/%s/status' % (self._url, quote(id_)),
            json=payload,
            **kwargs
        )

    @route('link')
    def _perform(self, id_, payload, **kwargs):
        return self._post(
            '%s/%s/link' % (self._url, quote(id_)),
            json=payload,
            **kwargs
        )

    @route('sightings.incidents')
    def _perform(self,
                 observable_type,
                 observable_value,
                 **kwargs):
        return self._get(
            '/ctia/%s/%s/sightings/incidents' % (quote(observable_type),
                                                 quote(observable_value)),
            **kwargs
        )
