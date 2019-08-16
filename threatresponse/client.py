from .api.enrich import EnrichAPI
from .api.inspect import InspectAPI
from .request.authorized import AuthorizedRequest
from .request.logged import LoggedRequest
from .request.standard import StandardRequest
from .request.relative import RelativeRequest


class ThreatResponse(object):

    _regions = {'NA': 'https://visibility.amp.cisco.com/',
                'EU': 'https://visibility.eu.amp.cisco.com/',
                'APJC': 'https://visibility.apjc.amp.cisco.com/'}

    def __init__(self, client_id, client_password, **options):
        request = StandardRequest()

        if options.get('logger'):
            request = LoggedRequest(request, options['logger'])

        request = RelativeRequest(request, self._base_url(options.get('region')))
        request = AuthorizedRequest(request, client_id, client_password)

        self._inspect = InspectAPI(request)
        self._enrich = EnrichAPI(request)

    @property
    def inspect(self):
        return self._inspect

    @property
    def enrich(self):
        return self._enrich

    def _base_url(self, region):
        return self._regions.get(region, self._regions['NA'])
