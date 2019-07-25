from .base import BaseAPI


class DeliberateAPI(BaseAPI):
    def observables(self, payload):
        return self._request.post('/iroh/iroh-enrich/deliberate/observables', json=payload).json()

    def sighting(self, payload):
        return self._request.post('/iroh/iroh-enrich/deliberate/sighting', json=payload).json()

    def sighting_ref(self, payload):
        return self._request.post('/iroh/iroh-enrich/deliberate/sighting_ref', json=payload).json()
