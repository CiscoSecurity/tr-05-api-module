from copy import deepcopy

from .base import API
from .routing import Router


class CommandsAPI(API):
    __router, route = Router.new()

    @route('verdict')
    def _perform(self, payload, **kwargs):
        """
        Command allow to simple query CTR
        for a verdict for a bunch of observables
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
        verdicts = build_array_for_verdicts(response)
        return {"response": response, "verdicts": verdicts}

    @route('targets')
    def _perform(self, payload, **kwargs):
        """
        Command allow to simple query CTR for a targets
        for a bunch of observables
        """

        response = self._post(
            '/iroh/iroh-inspect/inspect',
            json={'content': str(payload)},
            **kwargs
        )

        response = self._post(
            '/iroh/iroh-enrich/observe/observables',
            json=response,
            **kwargs
        )

        result = build_array_for_targets(response)

        return {"response": response, "targets": result}


def build_array_for_verdicts(verdict_dict):
    verdicts = []

    # According to the official documentation, `disposition_name` is
    # optional, so simply infer it from required `disposition`.
    disposition_map = {
        1: 'Clean',
        2: 'Malicious',
        3: 'Suspicious',
        4: 'Common',
        5: 'Unknown',
    }

    for module in verdict_dict.get('data', []):
        module_name = module['module']
        module_type_id = module['module_type_id']
        module_instance_id = module['module_instance_id']

        for doc in module.get('data', {}) \
                .get('verdicts', {}) \
                .get('docs', []):
            verdicts.append({
                'observable_value': doc['observable']['value'],
                'observable_type': doc['observable']['type'],
                'expiration': doc['valid_time'].get('end_time', ''),
                'module': module_name,
                'module_type_id': module_type_id,
                'module_instance_id': module_instance_id,
                'disposition_name': disposition_map[doc['disposition']],
            })

    return verdicts


def build_array_for_targets(targets_dict):
    result = []

    for module in targets_dict.get('data', []):
        module_name = module['module']
        module_type_id = module['module_type_id']
        module_instance_id = module['module_instance_id']
        targets = []

        for doc in module.get('data', {}) \
                .get('sightings', {}) \
                .get('docs', []):

            for target in doc.get('targets', []):
                element = deepcopy(target)
                element.pop('observed_time', None)
                if element not in targets:
                    targets.append(element)

        result.append({
            'module': module_name,
            'module_type_id': module_type_id,
            'module_instance_id': module_instance_id,
            'targets': targets
        })
    return result
