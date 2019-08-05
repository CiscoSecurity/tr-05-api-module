from ..base import API


class ReferAPI(API):

    def observables(self, payload):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Refer/post_iroh_iroh_enrich_refer_observables
        """

        response = self._request.post(
            '/iroh/iroh-enrich/refer/observables',
            json=payload,
        )
        response.raise_for_status()
        return response.json()
