from .base import API
from .routing import Router


class BundleAPI(API):
    """https://private.intel.amp.cisco.com/index.html#/Bundle"""

    __router, route = Router.new()

    @route('export.get')
    def _perform(self, **params):
        return self._get('/ctia/bundle/export', params=params)

    @route('export.post')
    def _perform(self, payload, **params):
        return self._post('/ctia/bundle/export', json=payload, params=params)

    @route('import.post')
    def _perform(self, payload, **params):
        return self._post('/ctia/bundle/import', json=payload, params=params)
