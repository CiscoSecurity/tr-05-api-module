from .deliberate import DeliberateAPI
from .observe import ObserveAPI
from .refer import ReferAPI
from ..base import API


class EnrichAPI(API):

    def __init__(self, request):
        super(EnrichAPI, self).__init__(request)

        self._deliberate = DeliberateAPI(self._request)
        self._observe = ObserveAPI(self._request)
        self._refer = ReferAPI(self._request)

    @property
    def deliberate(self):
        return self._deliberate

    @property
    def observe(self):
        return self._observe

    @property
    def refer(self):
        return self._refer

    def health(self):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Health/post_iroh_iroh_enrich_health
        """

        response = self._request.post('/iroh/iroh-enrich/health')
        response.raise_for_status()
        return response.json()
