from threatresponse.api.base import API


class ObserveAPI(API):

    def observables(self, payload):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Observe/post_iroh_iroh_enrich_observe_observables

        :param payload: JSON
        :return: JSON
        """

        return self._request.post('/iroh/iroh-enrich/observe/observables', payload).json()

    def sighting(self, payload):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Observe/post_iroh_iroh_enrich_observe_sighting

        :param payload: JSON
        :return: JSON
        """

        return self._request.post('/iroh/iroh-enrich/observe/sighting', payload).json()

    def sighting_ref(self, payload):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Observe/post_iroh_iroh_enrich_observe_sighting_ref

        :param payload: string
        :return: JSON
        """

        return self._request.post('/iroh/iroh-enrich/observe/sighting_ref', payload).json()
