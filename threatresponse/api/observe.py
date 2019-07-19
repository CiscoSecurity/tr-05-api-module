from .base import BaseAPI
from ..utils import raise_for_status


class ObserveAPI(BaseAPI):

    def __make_request(self, path, payload):
        url = self.absolute_url(path)
        response = self._request.post(url, json=payload)
        raise_for_status(response)
        return response.json()

    def observables(self, observable):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Observe/post_iroh_iroh_enrich_observe_observables

        :param observable: JSON
        :return: JSON
        """

        return self.__make_request('/iroh/iroh-enrich/observe/observables', observable)

    def sighting(self, sighting):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Observe/post_iroh_iroh_enrich_observe_sighting

        :param sighting: JSON
        :return: JSON
        """

        return self.__make_request('/iroh/iroh-enrich/observe/sighting', sighting)

    def sighting_ref(self, sighting_reference):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Observe/post_iroh_iroh_enrich_observe_sighting_ref

        :param sighting_reference: JSON
        :return: JSON
        """

        return self.__make_request('iroh/iroh-enrich/observe/sighting_ref', sighting_reference)
