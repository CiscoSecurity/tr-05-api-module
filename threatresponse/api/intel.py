from .base import API
from .bundle import BundleAPI
from .casebook import CasebookAPI
from .entity import IntelEntityAPI
from .event import EventAPI
from .incident import IncidentAPI
from .indicator import IndicatorAPI
from .judgement import JudgementAPI
from .routing import Router
from .sighting import SightingAPI
from .feed import FeedAPI
from .. import urls


class IntelAPI(API):
    """https://private.intel.amp.cisco.com/index.html"""

    __router, route = Router.new()

    def __init__(self, request):
        super(IntelAPI, self).__init__(request)

        self._actor = IntelEntityAPI(request, '/ctia/actor')
        self._actor.__doc__ = \
            "https://private.intel.amp.cisco.com/index.html#/Actor"

        self._campaign = IntelEntityAPI(request, '/ctia/campaign')
        self._campaign.__doc__ = \
            "https://private.intel.amp.cisco.com/index.html#/Campaign"

        self._coa = IntelEntityAPI(request, '/ctia/coa')
        self._coa.__doc__ = \
            "https://private.intel.amp.cisco.com/index.html#/COA"

        self._data_table = IntelEntityAPI(request, '/ctia/data-table')
        self._data_table.__doc__ = \
            "https://private.intel.amp.cisco.com/index.html#/DataTable"

        self._attack_pattern = IntelEntityAPI(request, '/ctia/attack-pattern')
        self._attack_pattern.__doc__ = \
            "https://private.intel.amp.cisco.com/index.html#/Attack_Pattern"

        self._feedback = IntelEntityAPI(request, '/ctia/feedback')
        self._feedback.__doc__ = \
            "https://private.intel.amp.cisco.com/index.html#/Feedback"

        self._graphql = IntelEntityAPI(request, '/ctia/graphql')
        self._graphql.__doc__ = \
            "https://private.intel.amp.cisco.com/index.html#/GraphQL"

        self._bulk = IntelEntityAPI(request, '/ctia/bulk')
        self._bulk.__doc__ = \
            "https://private.intel.amp.cisco.com/index.html#/Bulk"

        self._malware = IntelEntityAPI(request, '/ctia/malware')
        self._malware.__doc__ = \
            "https://private.intel.amp.cisco.com/index.html#/Malware"

        self._relationship = IntelEntityAPI(request, '/ctia/relationship')
        self._relationship.__doc__ = \
            "https://private.intel.amp.cisco.com/index.html#/Relationship"

        self._tool = IntelEntityAPI(request, '/ctia/tool')
        self._tool.__doc__ = \
            "https://private.intel.amp.cisco.com/index.html#/Tool"

        self._investigation = IntelEntityAPI(request, '/ctia/investigation')
        self._investigation.__doc__ = \
            "https://private.intel.amp.cisco.com/index.html#/Investigation"

        self._vulnerability = IntelEntityAPI(request, '/ctia/vulnerability')
        self._vulnerability.__doc__ = \
            "https://private.intel.amp.cisco.com/index.html#/Vulnerability"

        self._weakness = IntelEntityAPI(request, '/ctia/weakness')
        self._weakness.__doc__ = \
            "https://private.intel.amp.cisco.com/index.html#/Weakness"

        self._identity_assertion = \
            IntelEntityAPI(request, '/ctia/identity-assertion')
        self._identity_assertion.__doc__ = \
            "https://private.intel.amp.cisco.com/index.html#/IdentityAssertion"

        self._bundle = BundleAPI(request)
        self._event = EventAPI(request)
        self._incident = IncidentAPI(request)
        self._indicator = IndicatorAPI(request)
        self._judgement = JudgementAPI(request)
        self._casebook = CasebookAPI(request)
        self._sighting = SightingAPI(request)
        self._feed = FeedAPI(request)

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
    def feed(self):
        return self._feed

    @property
    def graphql(self):
        return self._graphql

    @property
    def event(self):
        return self._event

    @property
    def identity_assertion(self):
        return self._identity_assertion

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
    def tool(self):
        return self._tool

    @property
    def investigation(self):
        return self._investigation

    @property
    def vulnerability(self):
        return self._vulnerability

    @property
    def weakness(self):
        return self._weakness

    @route('properties.get')
    def _perform(self, **kwargs):
        """
        https://private.intel.amp.cisco.com/index.html#/Properties
        """

        return self._get('/ctia/properties', **kwargs)

    @route('metrics.get')
    def _perform(self, **kwargs):
        """
        https://private.intel.amp.cisco.com/index.html#/Metrics
        """

        return self._get('/ctia/metrics', **kwargs)

    @route('verdict.get')
    def _perform(self,
                 observable_type,
                 observable_value,
                 **kwargs):
        """
        https://private.intel.amp.cisco.com/index.html#/Verdict
        """

        return self._get(
            urls.join('/ctia', observable_type, observable_value, 'verdict'),
            **kwargs
        )

    @route('status.get')
    def _perform(self, **kwargs):
        """
        https://private.intel.amp.cisco.com/index.html#/Status
        """

        return self._get('/ctia/status', **kwargs)

    @route('version.get')
    def _perform(self, **kwargs):
        """
        https://private.intel.amp.cisco.com/index.html#/Version
        """

        return self._get('/ctia/version', **kwargs)
