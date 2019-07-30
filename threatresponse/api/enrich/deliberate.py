from ...api.base import API


class DeliberateAPI(API):

    def observables(self, payload):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Deliberate/post_iroh_iroh_enrich_deliberate_observables
        """

        return self._request.post('/iroh/iroh-enrich/deliberate/observables',
                                  json=payload).json()

    def sighting(self, payload):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Deliberate/post_iroh_iroh_enrich_deliberate_sighting
        """

        return self._request.post('/iroh/iroh-enrich/deliberate/sighting',
                                  json=payload).json()

    def sighting_ref(self, payload):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Deliberate/post_iroh_iroh_enrich_deliberate_sighting_ref
        """

        return self._request.post('/iroh/iroh-enrich/deliberate/sighting_ref',
                                  json=payload).json()
