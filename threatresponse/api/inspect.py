from .base import API


class InspectAPI(API):

    def inspect(self, payload):
        """
        https://visibility.amp.cisco.com/iroh/iroh-inspect/index.html#!/INSPECT/post_iroh_iroh_inspect_inspect
        """

        response = self._request.post(
            '/iroh/iroh-inspect/inspect',
            json=payload,
        )
        response.raise_for_status()
        return response.json()
