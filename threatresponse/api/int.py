from .base import API
from .routing import Router
from .entity import EntityAPI


class IntAPI(API):
    __router, route = Router.new()

    def __init__(self, request):
        super(IntAPI, self).__init__(request)

        self._integration = EntityAPI(
            request, '/iroh/iroh-int/integration')
        self._integration.__doc__ = "https://visibility.amp.cisco.com/iroh/" \
                                    "iroh-int/index.html#/Integration"

        self._module_instance = EntityAPI(
            request, '/iroh/iroh-int/module-instance')
        self._integration.__doc__ = "https://visibility.amp.cisco.com/iroh/" \
                                    "iroh-int/index.html#/ModuleInstance"

        self._module_type = EntityAPI(
            request, '/iroh/iroh-int/module-type')
        self._integration.__doc__ = "https://visibility.amp.cisco.com/iroh/" \
                                    "iroh-int/index.html#/ModuleType"

    @property
    def integration(self):
        return self._integration

    @property
    def module_instance(self):
        return self._module_instance

    @property
    def module_type(self):
        return self._module_type
