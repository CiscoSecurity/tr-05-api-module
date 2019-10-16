from .base import API
from .routing import Router


class EnrichAPI(API):
    __router, route = Router.new()

    @route('health')
    def _perform(self, response_type='json'):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Health/post_iroh_iroh_enrich_health
        """

        return self._post(
            '/iroh/iroh-enrich/health',
            response_type=response_type
        )

    @route('deliberate.observables')
    def _perform(self, payload, response_type='json'):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Deliberate/post_iroh_iroh_enrich_deliberate_observables
        """

        return self._post(
            '/iroh/iroh-enrich/deliberate/observables',
            json=payload,
            response_type=response_type
        )

    @route('observe.observables')
    def _perform(self, payload, response_type='json'):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Observe/post_iroh_iroh_enrich_observe_observables
        """

        return self._post(
            '/iroh/iroh-enrich/observe/observables',
            json=payload,
            response_type=response_type
        )

    @route('refer.observables')
    def _perform(self, payload, response_type='json'):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Refer/post_iroh_iroh_enrich_refer_observables
        """

        return self._post(
            '/iroh/iroh-enrich/refer/observables',
            json=payload,
            response_type=response_type
        )
