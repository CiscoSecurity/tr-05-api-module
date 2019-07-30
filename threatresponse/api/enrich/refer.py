from threatresponse.api.base import API


class ReferAPI(API):

    def observables(self, payload):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Refer/post_iroh_iroh_enrich_refer_observables

        :param payload: JSON
        :return: JSON
        """
        return self._request.post('/iroh/iroh-enrich/refer/observables',
                                  json=payload).json()

    def sighting(self, payload):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Refer/post_iroh_iroh_enrich_refer_sighting

        :param payload: JSON
        :return: JSON
        """
        return self._request.post('/iroh/iroh-enrich/refer/sighting',
                                  json=payload).json()

    def sighting_ref(self, payload):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Refer/post_iroh_iroh_enrich_refer_sighting_ref

        :param payload: JSON
        :return: JSON
        """
        return self._request.post('/iroh/iroh-enrich/refer/sighting_ref',
                                  json=payload).json()
