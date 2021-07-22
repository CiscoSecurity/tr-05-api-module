from .base import API
from .routing import Router


class BundleAPI(API):
    """https://private.intel.amp.cisco.com/index.html#/Bundle"""

    __router, route = Router.new()

    @route('export.get')
    def _perform(self, **kwargs):
        return self._get(
            '/ctia/bundle/export',
            **kwargs
        )

    @route('export.post')
    def _perform(self, payload, **kwargs):
        return self._post(
            '/ctia/bundle/export',
            json=payload,
            **kwargs
        )

    @route('import_.post')
    def _perform(self, payload, **kwargs):
        return self._post(
            '/ctia/bundle/import',
            json=payload,
            **kwargs
        )
