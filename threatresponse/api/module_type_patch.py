from .entity import EntityAPI
from .. import urls


class ModuleTypePatchAPI(EntityAPI):
    """
    https://visibility.amp.cisco.com/iroh/iroh-int/index.html#/ModuleTypePatch
    """
    URL = '/iroh/iroh-int/module-type-patch'

    def __init__(self, request):
        super(ModuleTypePatchAPI, self).__init__(request, self.URL)

    def action_preview(self, id_, **kwargs):
        return self._get(
            urls.join(self._url, id_, 'action/preview'),
            **kwargs
        )
