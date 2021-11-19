from .base import API
from .routing import Router
from .. import urls


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

    @route('health.module_instance_id')
    def _perform(self, module_instance_id, **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#/Health/post_iroh_iroh_enrich_health__module_instance_id_
        """

        return self._post(
            urls.join('/iroh/iroh-enrich/health', module_instance_id),
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

    @route('deliberate.sighting')
    def _perform(self, payload, **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#/Deliberate/post_iroh_iroh_enrich_deliberate_sighting
        """

        return self._post(
            '/iroh/iroh-enrich/deliberate/sighting',
            json=payload,
            **kwargs
        )

    @route('deliberate.sighting_ref')
    def _perform(self, payload, **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#/Deliberate/post_iroh_iroh_enrich_deliberate_sighting_ref
        """

        return self._post(
            '/iroh/iroh-enrich/deliberate/sighting_ref',
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

    @route('observe.sighting')
    def _perform(self, payload, **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#/Observe/post_iroh_iroh_enrich_observe_sighting
        """

        return self._post(
            '/iroh/iroh-enrich/observe/sighting',
            json=payload,
            **kwargs
        )

    @route('observe.sighting_ref')
    def _perform(self, payload, **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#/Observe/post_iroh_iroh_enrich_observe_sighting_ref
        """

        return self._post(
            '/iroh/iroh-enrich/observe/sighting_ref',
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

    @route('refer.sighting')
    def _perform(self, payload, **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#/Refer/post_iroh_iroh_enrich_refer_sighting
        """

        return self._post(
            '/iroh/iroh-enrich/refer/sighting',
            json=payload,
            **kwargs
        )

    @route('refer.sighting_ref')
    def _perform(self, payload, **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#/Refer/post_iroh_iroh_enrich_refer_sighting_ref
        """

        return self._post(
            '/iroh/iroh-enrich/refer/sighting_ref',
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
