from .routing import Router
from .base import API


class IntelAPI(API):
    __router, route = Router.new()

    # Actor

    @route('actor.post')
    def _perform(self, payload):
        """
        https://private.intel.amp.cisco.com/index.html#!/Actor/post_ctia_actor
        """

        response = self._request.post(
            '/ctia/actor',
            json=payload
        )
        response.raise_for_status()
        return response.json()

    @route('actor.delete')
    def _perform(self, id_):
        """
        https://private.intel.amp.cisco.com/index.html#!/Actor/delete_ctia_actor_id
        """

        response = self._request.delete(
            '/ctia/actor/{}'.format(id_)
        )
        response.raise_for_status()
        return response.json()

    @route('actor.get')
    def _perform(self, id_, **params):
        """
        https://private.intel.amp.cisco.com/index.html#!/Actor/get_ctia_actor_id
        """

        response = self._request.get(
            '/ctia/actor/{}'.format(id_),
            params=params
        )
        response.raise_for_status()
        return response.json()

    @route('actor.put')
    def _perform(self, id_, payload):
        """
        https://private.intel.amp.cisco.com/index.html#!/Actor/put_ctia_actor_id
        """

        response = self._request.put(
            '/ctia/actor/{}'.format(id_),
            json=payload
        )
        response.raise_for_status()
        return response.json()

    @route('actor.external_id')
    def _perform(self, id_, **params):
        """
        https://private.intel.amp.cisco.com/index.html#!/Actor/get_ctia_actor_external_id_external_id
        """

        response = self._request.get(
            '/ctia/actor/external_id/{}'.format(id_),
            params=params
        )
        response.raise_for_status()
        return response.json()

    @route('actor.search')
    def _perform(self, **params):
        """
        https://private.intel.amp.cisco.com/index.html#!/Actor/get_ctia_actor_search
        """

        response = self._request.get(
            '/ctia/actor/search',
            params=params
        )
        response.raise_for_status()
        return response.json()

    # Attack Pattern

    @route('attack_pattern.post')
    def _perform(self, payload):
        """
        https://private.intel.amp.cisco.com/index.html#!/Attack_Pattern/post_ctia_attack_pattern
        """

        response = self._request.post(
            '/ctia/attack-pattern',
            json=payload
        )
        response.raise_for_status()
        return response.json()

    @route('attack_pattern.delete')
    def _perform(self, id_):
        """
        https://private.intel.amp.cisco.com/index.html#!/Attack_Pattern/delete_ctia_attack_pattern_id
        """

        response = self._request.delete(
            '/ctia/attack-pattern/{}'.format(id_)
        )
        response.raise_for_status()
        return response.json()

    @route('attack_pattern.get')
    def _perform(self, id_, **params):
        """
        https://private.intel.amp.cisco.com/index.html#!/Attack_Pattern/get_ctia_attack_pattern_id
        """

        response = self._request.get(
            '/ctia/attack-pattern/{}'.format(id_),
            params=params
        )
        response.raise_for_status()
        return response.json()

    @route('attack_pattern.put')
    def _perform(self, id_, payload):
        """
        https://private.intel.amp.cisco.com/index.html#!/Attack_Pattern/put_ctia_attack_pattern_id
        """

        response = self._request.put(
            '/ctia/attack-pattern/{}'.format(id_),
            json=payload
        )
        response.raise_for_status()
        return response.json()

    @route('attack_pattern.external_id')
    def _perform(self, id_, **params):
        """
        https://private.intel.amp.cisco.com/index.html#!/Attack_Pattern/get_ctia_attack_pattern_external_id_external_id
        """

        response = self._request.get(
            '/ctia/attack-pattern/external_id/{}'.format(id_),
            params=params
        )
        response.raise_for_status()
        return response.json()

    @route('attack_pattern.search')
    def _perform(self, **params):
        """
        https://private.intel.amp.cisco.com/index.html#!/Attack_Pattern/get_ctia_attack_pattern_search
        """

        response = self._request.get(
            '/ctia/attack-pattern/search',
            params=params
        )
        response.raise_for_status()
        return response.json()
