from .base import BaseAPI


class EnrichAPI(BaseAPI):
    def health(self):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Health/post_iroh_iroh_enrich_health
        :return: JSON
        """

        url = self.absolute_url('/iroh/iroh-enrich/health')
        response = self._request.post(url)
        return response.json()
