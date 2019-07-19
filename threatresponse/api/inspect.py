from .base import BaseAPI
from ..utils import raise_for_status


class InspectAPI(BaseAPI):

    def inspect(self, payload):
        """
        https://visibility.amp.cisco.com/iroh/iroh-inspect/index.html#!/INSPECT/post_iroh_iroh_inspect_inspect

        :param payload: JSON
        :return: JSON
        """

        url = self.absolute_url('/iroh/iroh-inspect/inspect')
        response = self._request.post(url, json=payload)
        raise_for_status(response)
        return response.json()
