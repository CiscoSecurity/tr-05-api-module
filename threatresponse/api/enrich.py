from .base import API
from .routing import Router


class EnrichAPI(API):
    __router, route = Router.new()

    @route('health')
    def _perform(self):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Health/post_iroh_iroh_enrich_health
        """

        return self._post('/iroh/iroh-enrich/health')

    @route('deliberate.observables')
    def _perform(self, payload):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Deliberate/post_iroh_iroh_enrich_deliberate_observables
        """

        return self._post(
            '/iroh/iroh-enrich/deliberate/observables',
            json=payload
        )

    @route('observe.observables')
    def _perform(self, payload):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Observe/post_iroh_iroh_enrich_observe_observables
        """

        return self._post(
            '/iroh/iroh-enrich/observe/observables',
            json=payload
        )

    @route('refer.observables')
    def _perform(self, payload):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Refer/post_iroh_iroh_enrich_refer_observables
        """

        return self._post(
            '/iroh/iroh-enrich/refer/observables',
            json=payload
        )
