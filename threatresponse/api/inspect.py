from .base import API
from .routing import Router


class InspectAPI(API):
    __router, route = Router.new()

    @route('inspect')
    def _perform(self, payload, response_type='json'):
        """
        https://visibility.amp.cisco.com/iroh/iroh-inspect/index.html#!/INSPECT/post_iroh_iroh_inspect_inspect
        """

        return self._post(
            '/iroh/iroh-inspect/inspect',
            json=payload,
            response_type=response_type
        )
