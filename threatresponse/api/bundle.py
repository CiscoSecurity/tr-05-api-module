from .base import API
from .routing import Router


class BundleAPI(API):
    """https://private.intel.amp.cisco.com/index.html#/Bundle"""

    __router, route = Router.new()

    @route('export.get')
    def _perform(self, response_type='json', **params):
        return self._get(
            '/ctia/bundle/export',
            params=params,
            response_type=response_type
        )

    @route('export.post')
    def _perform(self, payload, response_type='json', **params):
        return self._post(
            '/ctia/bundle/export',
            json=payload,
            params=params,
            response_type=response_type
        )

    @route('import_.post')
    def _perform(self, payload, response_type='json', **params):
        return self._post(
            '/ctia/bundle/import',
            json=payload,
            params=params,
            response_type=response_type
        )
