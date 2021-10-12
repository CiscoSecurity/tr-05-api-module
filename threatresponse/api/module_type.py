from .base import API
from .routing import Router
from .. import urls


class ModuleTypeAPI(API):
    __router, route = Router.new()

    @route('get_all')
    def _perform(self, **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/iroh-int/index.html#/ModuleType/get_iroh_iroh_int_module_type
        """

        return self._get(
            '/iroh/iroh-int/module-type',
            **kwargs
        )

    @route('get_by_id')
    def _perform(self, module_id, **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/iroh-int/index.html#/ModuleType/get_iroh_iroh_int_module_type__id_
        """

        return self._get(
            urls.join('/iroh/iroh-int/module-type', module_id),
            **kwargs
        )

    @route('post')
    def _perform(self,
                 payload,
                 **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/iroh-int/index.html#/ModuleType/post_iroh_iroh_int_module_type
        """

        return self._post(
            '/iroh/iroh-int/module-type',
            json=payload,
            **kwargs
        )

    @route('patch')
    def _perform(self,
                 module_id,
                 payload,
                 **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/iroh-int/index.html#/ModuleType/patch_iroh_iroh_int_module_type__id_
        """

        return self._patch(
            urls.join('/iroh/iroh-int/module-type', module_id),
            json=payload,
            **kwargs
        )

    @route('delete')
    def _perform(self, module_id, **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/iroh-int/index.html#/ModuleType/delete_iroh_iroh_int_module_type__id_
        """

        return self._delete(
            urls.join('/iroh/iroh-int/module-type', module_id),
            **kwargs
        )
