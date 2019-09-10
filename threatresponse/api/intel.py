from .entity import EntityAPI
from .base import API


class IntelAPI(API):

    def __init__(self, request):
        super(IntelAPI, self).__init__(request)

        self._actor = EntityAPI(request, '/ctia/actor')
        self._actor.__doc__ = \
            "https://private.intel.amp.cisco.com/index.html#!/Actor/"
        self._campaign = EntityAPI(request, '/ctia/campaign')
        self._campaign.__doc__ = \
            "https://private.intel.amp.cisco.com/index.html#!/Campaign/"
        self._coa = EntityAPI(request, '/ctia/coa')
        self._coa.__doc__ = \
            "https://private.intel.amp.cisco.com/index.html#!/COA/"
        self._data_table = EntityAPI(request, '/ctia/data_table')
        self._data_table.__doc__ = \
            "https://private.intel.amp.cisco.com/index.html#!/DataTable/"


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
