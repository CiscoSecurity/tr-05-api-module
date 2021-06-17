from .entity import IntelEntityAPI
from .routing import Router
from .. import urls


class AssetAPI(IntelEntityAPI):

    __router, route = Router.new()

    @route('expire')
    def _perform(self, id_, payload, **kwargs):
        return self._post(
            urls.join(self._url, id_, 'expire'),
            json=payload,
            **kwargs
        )
