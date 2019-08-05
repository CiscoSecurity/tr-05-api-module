from ..base import API


class ObserveAPI(API):

    def observables(self, payload):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Observe/post_iroh_iroh_enrich_observe_observables
        """

        response = self._request.post(
            '/iroh/iroh-enrich/observe/observables',
            json=payload,
        )
        response.raise_for_status()
        return response.json()
