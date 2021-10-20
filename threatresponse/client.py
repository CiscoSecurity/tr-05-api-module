from .api.enrich import EnrichAPI
from .api.int import IntAPI
from .api.inspect import InspectAPI
from .api.intel import PrivateIntel, GlobalIntel
from .api.profile import ProfileAPI
from .api.response import ResponseAPI
from .api.commands import CommandsAPI
from .api.sse import SSEDeviceAPI, SSETenantAPI
from .api.user_mgmt import UserMgmtAPI
from .exceptions import CredentialsError
from .request.authorized import ClientAuthorizedRequest, TokenAuthorizedRequest
from .request.logged import LoggedRequest
from .request.proxied import ProxiedRequest
from .request.relative import RelativeRequest
from .request.standard import StandardRequest
from .request.timed import TimedRequest
from .urls import url_for


class ThreatResponse(object):

    def __init__(self, client_id=None, client_password=None,
                 token=None, **options):

        proxy = options.get('proxy')
        timeout = options.get('timeout')
        logger = options.get('logger')
        region = options.get('region')
        environment = options.get('environment')

        request = ProxiedRequest(proxy) if proxy else StandardRequest()
        request = TimedRequest(request, timeout) if timeout else request
        request = LoggedRequest(request, logger) if logger else request
        if token:
            request = TokenAuthorizedRequest(request,
                                             token,
                                             region=region,
                                             environment=environment)
        elif client_id and client_password:
            request = ClientAuthorizedRequest(request,
                                              client_id,
                                              client_password,
                                              region=region,
                                              environment=environment)
        else:
            raise CredentialsError(
                'Credentials must be supplied either '
                'as a pair of client_id and client_password or '
                'as a single token.'
            )

        def request_for(family):
            return RelativeRequest(
                request,
                url_for(region, family, environment)
            )

        self._inspect = InspectAPI(request_for('visibility'))
        self._enrich = EnrichAPI(request_for('visibility'))
        self._int = IntAPI(request_for('visibility'))
        self._response = ResponseAPI(request_for('visibility'))
        self._private_intel = PrivateIntel(request_for('private_intel'))
        self._profile = ProfileAPI(request_for('visibility'))
        self._global_intel = GlobalIntel(request_for('global_intel'))
        self._commands = CommandsAPI(request_for('visibility'))
        self._user_mgmt = UserMgmtAPI(request_for('visibility'))
        self._sse_device = SSEDeviceAPI(request_for('visibility'))
        self._sse_tenant = SSETenantAPI(request_for('visibility'))

    @property
    def inspect(self):
        return self._inspect

    @property
    def enrich(self):
        return self._enrich

    @property
    def int(self):
        return self._int

    @property
    def response(self):
        return self._response

    @property
    def private_intel(self):
        return self._private_intel

    @property
    def profile(self):
        return self._profile

    @property
    def global_intel(self):
        return self._global_intel

    @property
    def commands(self):
        return self._commands

    @property
    def user_mgmt(self):
        return self._user_mgmt

    @property
    def sse_device(self):
        return self._sse_device

    @property
    def sse_tenant(self):
        return self._sse_tenant
