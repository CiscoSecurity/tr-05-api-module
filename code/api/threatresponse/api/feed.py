from .entity import IntelEntityAPI
from .routing import Router
from .. import urls


class FeedAPI(IntelEntityAPI):
    """https://private.intel.amp.cisco.com/index.html#/Feed"""

    __router, route = Router.new()

    def __init__(self, request):
        super(FeedAPI, self).__init__(request, '/ctia/feed')

    @route('view')
    def _perform(self, id_, share_token, **kwargs):
        return self._get(
            urls.join(self._url, id_, 'view'),
            params={'s': share_token},
            **kwargs
        )

    @route('view.txt')
    def _perform(self, id_, share_token, **kwargs):
        return self._get(
            urls.join(self._url, id_, 'view.txt'),
            params={'s': share_token},
            response_type='text',
            **kwargs
        )
