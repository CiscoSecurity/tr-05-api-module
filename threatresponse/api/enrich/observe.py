from ...api.base import API


class ObserveAPI(API):

    def observables(self, payload):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Observe/post_iroh_iroh_enrich_observe_observables
        """

        return self._request.post('/iroh/iroh-enrich/observe/observables',
                                  json=payload).json()

    def sighting(self, payload):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Observe/post_iroh_iroh_enrich_observe_sighting
        """

        return self._request.post('/iroh/iroh-enrich/observe/sighting',
                                  json=payload).json()

    def sighting_ref(self, payload):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Observe/post_iroh_iroh_enrich_observe_sighting_ref
        """

        return self._request.post('/iroh/iroh-enrich/observe/sighting_ref',
                                  json=payload).json()
