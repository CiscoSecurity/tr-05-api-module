from .api.intel import IntelAPI
from .api.enrich import EnrichAPI
from .api.inspect import InspectAPI
from .request.authorized import AuthorizedRequest
from .request.logged import LoggedRequest
from .request.relative import RelativeRequest
from .request.standard import StandardRequest
from .urls import url_for


class ThreatResponse(object):

    def __init__(self, client_id, client_password, **options):
        credentials = (client_id, client_password)

        logger = options.get('logger')
        region = options.get('region')

        request = StandardRequest()
        request = LoggedRequest(request, logger) if logger else request
        request = AuthorizedRequest(request, *credentials, region=region)

        def request_for(family):
            return RelativeRequest(request, url_for(region, family))

        self._inspect = InspectAPI(request_for('visibility'))
        self._enrich = EnrichAPI(request_for('visibility'))
        self._private_intel = IntelAPI(request_for('private_intel'))
        self._global_intel = IntelAPI(request_for('global_intel'))

    @property
    def inspect(self):
        return self._inspect

    @property
    def enrich(self):
        return self._enrich

    @property
    def private_intel(self):
        return self._private_intel

    @property
    def global_intel(self):
        return self._global_intel
