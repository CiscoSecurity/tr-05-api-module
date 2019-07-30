from .deliberate import DeliberateAPI
from .observe import ObserveAPI
from .refer import ReferAPI
from ..base import API


class EnrichAPI(API):

    def __init__(self, request):
        super(EnrichAPI, self).__init__(request)

        self._deliberate = DeliberateAPI(request)
        self._observe = ObserveAPI(request)
        self._refer = ReferAPI(request)

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

        return self._request.post('/iroh/iroh-enrich/health').json()
