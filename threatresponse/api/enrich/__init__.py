from threatresponse.api.base import API
from .deliberate import DeliberateAPI
from .observe import ObserveAPI


class EnrichAPI(API):
    def __init__(self, request):
        super(EnrichAPI, self).__init__(request)

        self._deliberate = DeliberateAPI(request)
        self._observe = ObserveAPI(request)

    @property
    def deliberate(self):
        return self._deliberate

    @property
    def observe(self):
        return self._observe

    def health(self):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Health/post_iroh_iroh_enrich_health
        :return: JSON
        """

        return self._request.post('/iroh/iroh-enrich/health').json()
