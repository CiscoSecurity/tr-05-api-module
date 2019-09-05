from .api.enrich import EnrichAPI
from .api.inspect import InspectAPI
from .api.campaign import CampaignAPI
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
        request = RelativeRequest(request, url_for(region, 'visibility'))

        self._inspect = InspectAPI(request)
        self._enrich = EnrichAPI(request)
        self._campaign = CampaignAPI(request)

    @property
    def inspect(self):
        return self._inspect

    @property
    def enrich(self):
        return self._enrich
