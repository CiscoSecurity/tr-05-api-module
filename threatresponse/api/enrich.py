from .base import API
from .routing import Router


class EnrichAPI(API):
    __router, route = Router.new()

    @route('health')
    def _perform(self):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Health/post_iroh_iroh_enrich_health
        """

        response = self._request.post('/iroh/iroh-enrich/health')
        response.raise_for_status()
        return response.json()

    @route('deliberate.observables')
    def _perform(self, payload):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Deliberate/post_iroh_iroh_enrich_deliberate_observables
        """

        response = self._request.post(
            '/iroh/iroh-enrich/deliberate/observables',
            json=payload,
        )
        response.raise_for_status()
        return response.json()

    @route('observe.observables')
    def _perform(self, payload):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Observe/post_iroh_iroh_enrich_observe_observables
        """

        response = self._request.post(
            '/iroh/iroh-enrich/observe/observables',
            json=payload,
        )
        response.raise_for_status()
        return response.json()

    @route('refer.observables')
    def _perform(self, payload):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Refer/post_iroh_iroh_enrich_refer_observables
        """

        response = self._request.post(
            '/iroh/iroh-enrich/refer/observables',
            json=payload,
        )
        response.raise_for_status()
        return response.json()
