from .base import API
from .routing import Router
from .. import urls


class ResponseAPI(API):
    __router, route = Router.new()

    @route('respond.observables')
    def _perform(self, payload, **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/iroh-response/index.html#/Response/post_iroh_iroh_response_respond_observables
        """

        return self._post(
            '/iroh/iroh-response/respond/observables',
            json=payload,
            **kwargs
        )

    @route('respond.sighting')
    def _perform(self, payload, **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/iroh-response/index.html#/Response/post_iroh_iroh_response_respond_sighting
        """

        return self._post(
            '/iroh/iroh-response/respond/sighting',
            json=payload,
            **kwargs
        )

    @route('respond.trigger')
    def _perform(self,
                 module_name,
                 action_id,
                 observable_type=None,
                 observable_value=None,
                 **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/iroh-response/index.html#/Response/post_iroh_iroh_response_respond_trigger__module_name___action_id_
        """

        url = urls.join(
            '/iroh/iroh-response/respond/trigger',
            module_name,
            action_id
        )

        # Extend optional module-specific query params with the required ones.
        query = kwargs.pop('params', {})
        if observable_type and observable_value:
            query.update({
                'observable_type': observable_type,
                'observable_value': observable_value,
            })

        return self._post(url, params=query, **kwargs)
