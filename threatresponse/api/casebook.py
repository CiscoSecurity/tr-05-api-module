from .entity import EntityAPI
from .routing import Router


class CasebookAPI(EntityAPI):
    """https://private.intel.amp.cisco.com/index.html#/Casebook"""

    __router, route = Router.new()

    def __init__(self, request):
        super(CasebookAPI, self).__init__(request, '/ctia/casebook')

    @route('observables')
    def _perform(self, id_, payload):
        return self._post('%s/%s/observables' % (self._url, id_),
                          json=payload)

    @route('texts')
    def _perform(self, id_, payload):
        return self._post('%s/%s/texts' % (self._url, id_),
                          json=payload)

    @route('bundle')
    def _perform(self, id_, payload):
        return self._post('%s/%s/bundle' % (self._url, id_),
                          json=payload)
