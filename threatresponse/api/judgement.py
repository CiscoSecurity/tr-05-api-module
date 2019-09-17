from .entity import EntityAPI
from .routing import Router


class JudgementAPI(EntityAPI):
    """https://private.intel.amp.cisco.com/index.html#/Judgement"""

    __router, route = Router.new()

    def __init__(self, request):
        super(JudgementAPI, self).__init__(request, '/ctia/judgement')

    @route('judgements')
    def _perform(self, observable_type, observable_value):
        return self._get(
            '/ctia/%s/%s/judgements' %
            (observable_type, observable_value)
        )
