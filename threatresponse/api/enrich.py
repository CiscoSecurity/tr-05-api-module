from .base import BaseAPI
from .deliberate import DeliberateAPI


class EnrichAPI(BaseAPI):
    def __init__(self, request):
        super(EnrichAPI, self).__init__(request)

        self._deliberate = DeliberateAPI(request)

    @property
    def deliberate(self):
        return self._deliberate

    def health(self):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Health/post_iroh_iroh_enrich_health
        :return: JSON
        """

        return self._request.post('/iroh/iroh-enrich/health').json()
