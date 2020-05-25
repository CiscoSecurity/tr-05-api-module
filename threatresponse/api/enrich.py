from .base import API
from .routing import Router


class EnrichAPI(API):
    __router, route = Router.new()

    @route('health')
    def _perform(self, **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#/Health/post_iroh_iroh_enrich_health
        """

        return self._post(
            '/iroh/iroh-enrich/health',
            **kwargs
        )

    @route('deliberate.observables')
    def _perform(self, payload, **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#/Deliberate/post_iroh_iroh_enrich_deliberate_observables
        """

        return self._post(
            '/iroh/iroh-enrich/deliberate/observables',
            json=payload,
            **kwargs
        )

    @route('observe.observables')
    def _perform(self, payload, **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#/Observe/post_iroh_iroh_enrich_observe_observables
        """

        return self._post(
            '/iroh/iroh-enrich/observe/observables',
            json=payload,
            **kwargs
        )

    @route('refer.observables')
    def _perform(self, payload, **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#/Refer/post_iroh_iroh_enrich_refer_observables
        """

        return self._post(
            '/iroh/iroh-enrich/refer/observables',
            json=payload,
            **kwargs
        )

    @route('settings.get')
    def _perform(self, **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#/Settings/get_iroh_iroh_enrich_settings
        """

        return self._get(
            '/iroh/iroh-enrich/settings',
            **kwargs
        )
