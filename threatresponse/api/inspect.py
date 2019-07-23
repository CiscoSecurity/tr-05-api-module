from .base import BaseAPI


class InspectAPI(BaseAPI):

    def inspect(self, payload):
        """
        https://visibility.amp.cisco.com/iroh/iroh-inspect/index.html#!/INSPECT/post_iroh_iroh_inspect_inspect

        :param payload: JSON
        :return: JSON
        """

        return self._post('/iroh/iroh-inspect/inspect', payload)
