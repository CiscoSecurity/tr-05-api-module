from .routing import Router
from .entity import EntityAPI
from .base import API


class IntelAPI(API):
    __router, route = Router.new()

    def __init__(self, request):
        super(IntelAPI, self).__init__(request)

        self._actor = EntityAPI(request, '/ctia/actor')
        self._actor.__doc__ = \
            "https://private.intel.amp.cisco.com/index.html#!/Actor"

        self._campaign = EntityAPI(request, '/ctia/campaign')
        self._campaign.__doc__ = \
            "https://private.intel.amp.cisco.com/index.html#!/Campaign/"

        self._coa = EntityAPI(request, '/ctia/coa')
        self._coa.__doc__ = \
            "https://private.intel.amp.cisco.com/index.html#!/COA/"

        self._data_table = EntityAPI(request, '/ctia/data_table')
        self._data_table.__doc__ = \
            "https://private.intel.amp.cisco.com/index.html#!/DataTable/"

        self._attack_pattern = EntityAPI(request, '/ctia/attack-pattern')
        self._attack_pattern.__doc__ = \
            "https://private.intel.amp.cisco.com/index.html#/Attack_Pattern"

    @property
    def actor(self):
        return self._actor

    @property
    def campaign(self):
        return self._campaign

    @property
    def coa(self):
        return self._coa

    @property
    def data_table(self):
        return self._data_table

    @property
    def attack_pattern(self):
        return self._attack_pattern

    @route('bundle.export.get')
    def _perform(self, **params):
        """
        https://private.intel.amp.cisco.com/index.html#!/Bundle/get_ctia_bundle_export
        """

        url = '/ctia/bundle/export'

        response = self._request.get(url, params=params)
        response.raise_for_status()

        return response.json()

    @route('bundle.export.post')
    def _perform(self, payload, **params):
        """
        https://private.intel.amp.cisco.com/index.html#!/Bundle/post_ctia_bundle_export
        """

        url = '/ctia/bundle/export'

        response = self._request.post(url, json=payload, params=params)
        response.raise_for_status()

        return response.json()

    @route('bundle.import.post')
    def _perform(self, payload, **params):
        """
        https://private.intel.amp.cisco.com/index.html#!/Bundle/post_ctia_bundle_import
        """

        url = '/ctia/bundle/import'

        response = self._request.post(url, json=payload, params=params)
        response.raise_for_status()

        return response.json()
