from .routing import Router
from .entity import EntityAPI
from .base import API
from .bundle import BundleAPI
from .incident import IncidentAPI
from .indicator import IndicatorAPI
from .judgement import JudgementAPI


class IntelAPI(API):
    """https://private.intel.amp.cisco.com/index.html"""

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

        self._data_table = EntityAPI(request, '/ctia/data-table')
        self._data_table.__doc__ = \
            "https://private.intel.amp.cisco.com/index.html#!/DataTable/"

        self._attack_pattern = EntityAPI(request, '/ctia/attack-pattern')
        self._attack_pattern.__doc__ = \
            "https://private.intel.amp.cisco.com/index.html#/Attack_Pattern"

        self._bundle = BundleAPI(request)
        self._incident = IncidentAPI(request)
        self._indicator = IndicatorAPI(request)
        self._judgement = JudgementAPI(request)

    @property
    def actor(self):
        return self._actor

    @property
    def bundle(self):
        return self._bundle

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

    @property
    def incident(self):
        return self._incident

    @property
    def indicator(self):
        return self._indicator

    @property
    def judgement(self):
        return self._judgement
