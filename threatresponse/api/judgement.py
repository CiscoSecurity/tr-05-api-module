from .entity import EntityAPI
from .routing import Router
from .. import urls


class JudgementAPI(EntityAPI):
    """https://private.intel.amp.cisco.com/index.html#/Judgement"""

    __router, route = Router.new()

    def __init__(self, request):
        super(JudgementAPI, self).__init__(request, '/ctia/judgement')

    @route('judgements')
    def _perform(self, observable_type, observable_value, **kwargs):
        return self._get(
            urls.join(
                '/ctia',
                observable_type,
                observable_value,
                'judgements'
            ),
            **kwargs
        )
