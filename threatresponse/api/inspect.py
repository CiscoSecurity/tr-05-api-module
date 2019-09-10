from .base import API
from .routing import Router


class InspectAPI(API):
    __router, route = Router.new()

    @route('inspect')
    def _perform(self, payload):
        """
        https://visibility.amp.cisco.com/iroh/iroh-inspect/index.html#!/INSPECT/post_iroh_iroh_inspect_inspect
        """

        response = self._request.post(
            '/iroh/iroh-inspect/inspect',
            json=payload,
        )
        response.raise_for_status()
        return response.json()
