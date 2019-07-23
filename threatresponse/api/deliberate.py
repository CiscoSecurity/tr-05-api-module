from .base import BaseAPI


class DeliberateAPI(BaseAPI):
    def observables(self, payload):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Deliberate/post_iroh_iroh_enrich_deliberate_observables

        :param payload: JSON?
        :return: JSON?
        """

        return self._post('/iroh/iroh-enrich/deliberate/observables', payload)

    def sighting(self, payload):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Deliberate/post_iroh_iroh_enrich_deliberate_sighting

        :param payload: JSON?
        :return: JSON?
        """

        return self._post('/iroh/iroh-enrich/deliberate/sighting', payload)

    def sighting_ref(self, payload):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Deliberate/post_iroh_iroh_enrich_deliberate_sighting_ref

        :param payload: JSON?
        :return: JSON?
        """

        return self._post('/iroh/iroh-enrich/deliberate/sighting_ref', payload)
