from .api.enrich import EnrichAPI
from .api.inspect import InspectAPI
from .api.campaign import CampaignAPI
from .api.coa import COAAPI
from .api.data_table import DataTableAPI
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
        visibility_request = RelativeRequest(
            request,
            url_for(region, 'visibility')
        )
        self._inspect = InspectAPI(visibility_request)
        self._enrich = EnrichAPI(visibility_request)

        private_intel_request = RelativeRequest(
            request,
            url_for(region, 'private_intel')
        )
        # global_intel_request = RelativeRequest(
        #     request,
        #     url_for(region, 'global_intel')
        # )

        self._campaign = CampaignAPI(private_intel_request)
        self._COA = COAAPI(private_intel_request)
        self._data_table = DataTableAPI(private_intel_request)

    @property
    def inspect(self):
        return self._inspect

    @property
    def enrich(self):
        return self._enrich

    @property
    def campaign(self):
        return self._campaign

    @property
    def coa(self):
        return self._COA

    @property
    def data_table(self):
        return self._data_table

