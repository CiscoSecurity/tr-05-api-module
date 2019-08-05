from ..base import API


class DeliberateAPI(API):

    def observables(self, payload):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Deliberate/post_iroh_iroh_enrich_deliberate_observables
        """

        response = self._request.post(
            '/iroh/iroh-enrich/deliberate/observables',
            json=payload,
        )
        response.raise_for_status()
        return response.json()
