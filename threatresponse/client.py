from .api.enrich import EnrichAPI
from .api.inspect import InspectAPI
from .request.authorized import AuthorizedRequest
from .request.logged import LoggedRequest
from .request.relative import RelativeRequest
from .request.standard import StandardRequest
from .urls import urls_for_region


class ThreatResponse(object):

    def __init__(self, client_id, client_password, **options):
        request = StandardRequest()

        logger = options.get('logger')
        if logger is not None:
            request = LoggedRequest(request, options['logger'])

        region = options.get('region')

        request = AuthorizedRequest(request, client_id, client_password, region)

        urls = urls_for_region(region)

        request = RelativeRequest(request, urls['visibility'])

        self._inspect = InspectAPI(request)
        self._enrich = EnrichAPI(request)

    @property
    def inspect(self):
        return self._inspect

    @property
    def enrich(self):
        return self._enrich
