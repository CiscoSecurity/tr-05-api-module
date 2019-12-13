from .base import API
from .routing import Router


class CommandsAPI(API):
    __router, route = Router.new()

    @route('verdict')
    def _perform(self, payload, **kwargs):
        """
        Command allow to simple query CTR for a verdict for a bunch of observables
        """

        response = self._post(
            '/iroh/iroh-inspect/inspect',
            json={'content': str(payload)},
            **kwargs
        )

        response = self._post(
            '/iroh/iroh-enrich/deliberate/observables',
            json=response,
            **kwargs
        )
        verdicts = []
        for module in response.get('data', []):
            module_name = module['module']

            for doc in module.get('data', {}).get('verdicts', {}).get('docs', []):
                verdicts.append({
                    'observable_value': doc['observable']['value'],
                    'observable_type': doc['observable']['type'],
                    'expiration': doc['valid_time']['end_time'],
                    'module': module_name,
                    'disposition_name': doc['disposition_name']
                })
        return {"response": response, "verdicts": verdicts}
