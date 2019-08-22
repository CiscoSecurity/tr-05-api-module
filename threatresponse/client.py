from .api.enrich import EnrichAPI
from .api.inspect import InspectAPI
from .exceptions import UnsupportedRegionError
from .request.authorized import AuthorizedRequest
from .request.logged import LoggedRequest
from .request.relative import RelativeRequest
from .request.standard import StandardRequest


class ThreatResponse(object):
    SUPPORTED_REGIONS = ('', '.eu', '.apjc')

    VISIBILITY_URL_PATTERN = 'https://visibility{region}.amp.cisco.com/'

    def __init__(self, client_id, client_password, **options):
        request = StandardRequest()

        logger = options.get('logger')
        if logger is not None:
            request = LoggedRequest(request, options['logger'])

        request = AuthorizedRequest(request, client_id, client_password)

        region = options.get('region') or ''
        if len(region) > 0 and not region.startswith('.'):
            region = '.' + region

        if region not in self.SUPPORTED_REGIONS:
            # Use `repr` to make each region enclosed in quotes.
            raise UnsupportedRegionError(
                'Region {} is unsupported, must be one of: {}.'.format(
                    repr(region),
                    ', '.join(map(repr, self.SUPPORTED_REGIONS)),
                )
            )

        request = RelativeRequest(
            request,
            self.VISIBILITY_URL_PATTERN.format(region=region),
        )

        self._inspect = InspectAPI(request)
        self._enrich = EnrichAPI(request)

    @property
    def inspect(self):
        return self._inspect

    @property
    def enrich(self):
        return self._enrich
