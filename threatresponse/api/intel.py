from .routing import Router
from .entity import EntityAPI
from .base import API
from .bundle import BundleAPI
from .incident import IncidentAPI
from .indicator import IndicatorAPI
from .judgement import JudgementAPI
from .event import EventAPI
from .sighting import SightingAPI
from .casebook import CasebookAPI


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

        self._feedback = EntityAPI(request, '/ctia/feedback')
        self._feedback.__doc__ = \
            "https://private.intel.amp.cisco.com/index.html#/Feedback"

        self._graphql = EntityAPI(request, '/ctia/graphql')
        self._graphql.__doc__ = \
            "https://private.intel.amp.cisco.com/index.html#/GraphQL"

        self._bulk = EntityAPI(request, '/ctia/bulk')
        self._bulk.__doc__ = \
            "https://private.intel.amp.cisco.com/index.html#/Bulk"

        self._malware = EntityAPI(request, '/ctia/malware')
        self._malware.__doc__ = \
            "https://private.intel.amp.cisco.com/index.html#/Malware"

        self._relationship = EntityAPI(request, '/ctia/relationship')
        self._relationship.__doc__ = \
            "https://private.intel.amp.cisco.com/index.html#/Relationship"

        self._investigation = EntityAPI(request, '/ctia/investigation')
        self._investigation.__doc__ = \
            "https://private.intel.amp.cisco.com/index.html#/Investigation"

        self._bundle = BundleAPI(request)
        self._event = EventAPI(request)
        self._incident = IncidentAPI(request)
        self._indicator = IndicatorAPI(request)
        self._judgement = JudgementAPI(request)
        self._casebook = CasebookAPI(request)
        self._sighting = SightingAPI(request)

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
    def feedback(self):
        return self._feedback

    @property
    def graphql(self):
        return self._graphql

    @property
    def event(self):
        return self._event

    @property
    def incident(self):
        return self._incident

    @property
    def indicator(self):
        return self._indicator

    @property
    def judgement(self):
        return self._judgement

    @property
    def casebook(self):
        return self._casebook

    @property
    def sighting(self):
        return self._sighting

    @property
    def bulk(self):
        return self._bulk

    @property
    def malware(self):
        return self._malware

    @property
    def relationship(self):
        return self._relationship

    @property
    def investigation(self):
        return self._investigation

    @route('properties.get')
    def _perform(self):
        """
        https://private.intel.amp.cisco.com/index.html#!/Properties/get_ctia_properties
        """

        return self._get('/ctia/properties')

    @route('status.get')
    def _perform(self):
        """
        https://private.intel.amp.cisco.com/index.html#/Status
        """

        return self._get('/ctia/status')

    @route('version.get')
    def _perform(self):
        """
        https://private.intel.amp.cisco.com/index.html#/Version
        """

        return self._get('/ctia/version')
