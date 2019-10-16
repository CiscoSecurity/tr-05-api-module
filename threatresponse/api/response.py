from six.moves.urllib.parse import quote

from .base import API
from .routing import Router


class ResponseAPI(API):
    __router, route = Router.new()

    @route('respond.observables')
    def _perform(self, payload, response_type='json'):
        """
        https://visibility.amp.cisco.com/iroh/iroh-response/index.html#/Response
        """

        return self._post(
            '/iroh/iroh-response/respond/observables',
            json=payload,
            response_type=response_type
        )

    @route('respond.trigger')
    def _perform(self,
                 module_name,
                 action_id,
                 observable_type,
                 observable_value,
                 response_type='json',
                 **query):
        """
        https://visibility.amp.cisco.com/iroh/iroh-response/index.html#!/Response/post_iroh_iroh_response_respond_trigger_module_name_action_id
        """

        url = '/iroh/iroh-response/respond/trigger/{}/{}'.format(
            quote(module_name),
            quote(action_id),
        )

        # Extend optional module-specific query params with the required ones.
        query.update({
            'observable_type': observable_type,
            'observable_value': observable_value,
        })

        return self._post(url, params=query, response_type=response_type)
