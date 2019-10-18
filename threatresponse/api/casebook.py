from six.moves.urllib.parse import quote

from .entity import EntityAPI
from .routing import Router


class CasebookAPI(EntityAPI):
    """https://private.intel.amp.cisco.com/index.html#/Casebook"""

    __router, route = Router.new()

    def __init__(self, request):
        super(CasebookAPI, self).__init__(request, '/ctia/casebook')

    @route('observables')
    def _perform(self, id_, payload, **kwargs):
        return self._post(
            '%s/%s/observables' % (self._url, quote(id_)),
            json=payload,
            **kwargs
        )

    @route('texts')
    def _perform(self, id_, payload, **kwargs):
        return self._post(
            '%s/%s/texts' % (self._url, quote(id_)),
            json=payload,
            **kwargs
        )

    @route('bundle')
    def _perform(self, id_, payload, **kwargs):
        return self._post(
            '%s/%s/bundle' % (self._url, quote(id_)),
            json=payload,
            **kwargs
        )
