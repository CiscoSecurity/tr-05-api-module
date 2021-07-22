from .entity import IntelEntityAPI
from .routing import Router
from .. import urls


class CasebookAPI(IntelEntityAPI):
    """https://private.intel.amp.cisco.com/index.html#/Casebook"""

    __router, route = Router.new()

    def __init__(self, request):
        super(CasebookAPI, self).__init__(request, '/ctia/casebook')

    @route('observables')
    def _perform(self, id_, payload, **kwargs):
        return self._post(
            urls.join(self._url, id_, 'observables'),
            json=payload,
            **kwargs
        )

    @route('texts')
    def _perform(self, id_, payload, **kwargs):
        return self._post(
            urls.join(self._url, id_, 'texts'),
            json=payload,
            **kwargs
        )

    @route('bundle')
    def _perform(self, id_, payload, **kwargs):
        return self._post(
            urls.join(self._url, id_, 'bundle'),
            json=payload,
            **kwargs
        )
