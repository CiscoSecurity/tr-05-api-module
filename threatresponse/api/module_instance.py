from .base import API
from .routing import Router
from .. import urls


class ModuleInstanceAPI(API):
    __router, route = Router.new()

    @route('get_all')
    def _perform(self, **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/iroh-int/index.html#/ModuleInstance/get_iroh_iroh_int_module_instance
        """

        return self._get(
            '/iroh/iroh-int/module-instance',
            **kwargs
        )

    @route('get_by_id')
    def _perform(self, instance_id, **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/iroh-int/index.html#/ModuleInstance/patch_iroh_iroh_int_module_instance__id_
        """

        return self._get(
            urls.join('/iroh/iroh-int/module-instance', instance_id),
            **kwargs
        )

    @route('post')
    def _perform(self,
                 payload,
                 **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/iroh-int/index.html#/ModuleInstance/post_iroh_iroh_int_module_instance
        """

        return self._post(
            '/iroh/iroh-int/module-instance',
            json=payload,
            **kwargs
        )

    @route('patch')
    def _perform(self,
                 instance_id,
                 payload,
                 **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/iroh-int/index.html#/ModuleInstance/patch_iroh_iroh_int_module_instance__id_
        """

        return self._patch(
            urls.join('/iroh/iroh-int/module-instance', instance_id),
            json=payload,
            **kwargs
        )

    @route('delete')
    def _perform(self, instance_id, **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/iroh-int/index.html#/ModuleInstance/delete_iroh_iroh_int_module_instance__id_
        """

        return self._delete(
            urls.join('/iroh/iroh-int/module-instance', instance_id),
            **kwargs
        )
