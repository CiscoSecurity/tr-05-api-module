from .base import BaseAPI
from ..api.deliberate import DeliberateAPI


class EnrichAPI(BaseAPI):
    def __init__(self, request):
        super(BaseAPI).__init__(request)

        self._deliberate = DeliberateAPI(request)

    @property
    def deliberate(self):
        return self._deliberate
