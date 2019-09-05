from .routing import Router
from .base import API


class CtiaAPI(API):
    __router, route = Router.new()

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
    def _perform(self, query, **params):
        """
        https://private.intel.amp.cisco.com/index.html#!/Actor/get_ctia_actor_search
        """

        params.update({'query': query})

        response = self._request.get(
            '/ctia/actor/search',
            params=params
        )
        response.raise_for_status()
        return response.json()
