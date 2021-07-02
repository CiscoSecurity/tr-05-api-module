from .entity import IntelEntityAPI
from .routing import Router
from .. import urls


class JudgementAPI(IntelEntityAPI):
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

    @route('expire')
    def _perform(self, id_, payload, **kwargs):
        return self._post(
            urls.join(self._url, id_, 'expire'),
            json=payload,
            **kwargs
        )
