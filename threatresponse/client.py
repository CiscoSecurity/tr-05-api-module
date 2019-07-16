from .api.enrich import EnrichAPI
from .api.inspect import InspectAPI
from .request.authorized import AuthorizedRequest
from .request.logged import LoggedRequest
from .request.standard import StandardRequest


class ThreatResponse(object):

    def __init__(self, client_id, client_password, **options):
        request = StandardRequest()
        if options.get('logger'):
            request = LoggedRequest(request, options['logger'])
        request = AuthorizedRequest(request, client_id, client_password)

        self._enrich = EnrichAPI(request)
        self._inspect = InspectAPI(request)

    @property
    def enrich(self):
        return self._enrich

    @property
    def inspect(self):
        return self._inspect
