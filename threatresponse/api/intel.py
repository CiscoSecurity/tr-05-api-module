from .routing import Router
from .base import API


def create_entity(prefix):
    def create_wrapper(f):

        def create(self, payload, **params):
            response = self._request.post(prefix, json=payload, params=params)
            response.raise_for_status()
            return response.json()

        return create
    return create_wrapper


def delete_entity(prefix):
    def delete_wrapper(f):

        def delete(self, id_):
            response = self._request.delete('{}/{}'.format(prefix, id_))
            response.raise_for_status()
            return response.json()

        return delete
    return delete_wrapper


def get_entity_by_id(prefix):
    def get_by_id_wrapper(f):

        def get(self, id_, **params):
            response = self._request.get(
                '{}/{}'.format(prefix, id_),
                params=params
            )
            response.raise_for_status()
            return response.json()

        return get
    return get_by_id_wrapper


def update_entity(prefix):
    def update_wrapper(f):

        def update(self, id_, payload):
            response = self._request.put(
                '{}/{}'.format(prefix, id_),
                json=payload
            )
            response.raise_for_status()
            return response.json()

        return update
    return update_wrapper


def get_entity_by_external_id(prefix):
    def get_by_external_id_wrapper(f):
        def get(self, id_, **params):
            response = self._request.get(
                '{}/external_id/{}'.format(prefix, id_),
                params=params
            )
            response.raise_for_status()
            return response.json()

        return get
    return get_by_external_id_wrapper


def search_entity(prefix):
    def search_wrapper(f):
        def search(self, **params):
            response = self._request.get(prefix + '/search', params=params)
            response.raise_for_status()
            return response.json()

        return search

    return search_wrapper


class IntelAPI(API):
    __router, route = Router.new()

    # Actor
    ACTOR_PREFIX = '/ctia/actor'
    
    @route('actor.post')
    @create_entity(ACTOR_PREFIX)
    def _perform(self, *args, **kwargs):
        """
        https://private.intel.amp.cisco.com/index.html#!/Actor/post_ctia_actor
        """
        pass

    @route('actor.delete')
    @delete_entity(ACTOR_PREFIX)
    def _perform(self, *args, **kwargs):
        """
        https://private.intel.amp.cisco.com/index.html#!/Actor/delete_ctia_actor_id
        """
        pass

    @route('actor.get')
    @get_entity_by_id(ACTOR_PREFIX)
    def _perform(self, *args, **kwargs):
        """
        https://private.intel.amp.cisco.com/index.html#!/Actor/get_ctia_actor_id
        """
        pass

    @route('actor.put')
    @update_entity(ACTOR_PREFIX)
    def _perform(self, *args, **kwargs):
        """
        https://private.intel.amp.cisco.com/index.html#!/Actor/put_ctia_actor_id
        """
        pass

    @route('actor.external_id')
    @get_entity_by_external_id(ACTOR_PREFIX)
    def _perform(self, *args, **kwargs):
        """
        https://private.intel.amp.cisco.com/index.html#!/Actor/get_ctia_actor_external_id_external_id
        """
        pass

    @route('actor.search')
    @search_entity(ACTOR_PREFIX)
    def _perform(self,  *args, **kwargs):
        """
        https://private.intel.amp.cisco.com/index.html#!/Actor/get_ctia_actor_search
        """
        pass

    # Attack Pattern
    ATTACK_PATTERN_PREFIX = '/ctia/actor'

    @route('attack_pattern.post')
    @create_entity(ATTACK_PATTERN_PREFIX)
    def _perform(self, *args, **kwargs):
        """
        https://private.intel.amp.cisco.com/index.html#!/Actor/post_ctia_actor
        """
        pass

    @route('attack_pattern.delete')
    @delete_entity(ATTACK_PATTERN_PREFIX)
    def _perform(self, *args, **kwargs):
        """
        https://private.intel.amp.cisco.com/index.html#!/Actor/delete_ctia_actor_id
        """
        pass

    @route('attack_pattern.get')
    @get_entity_by_id(ATTACK_PATTERN_PREFIX)
    def _perform(self, *args, **kwargs):
        """
        https://private.intel.amp.cisco.com/index.html#!/Actor/get_ctia_actor_id
        """
        pass

    @route('attack_pattern.put')
    @update_entity(ATTACK_PATTERN_PREFIX)
    def _perform(self, *args, **kwargs):
        """
        https://private.intel.amp.cisco.com/index.html#!/Actor/put_ctia_actor_id
        """
        pass

    @route('attack_pattern.external_id')
    @get_entity_by_external_id(ATTACK_PATTERN_PREFIX)
    def _perform(self, *args, **kwargs):
        """
        https://private.intel.amp.cisco.com/index.html#!/Actor/get_ctia_actor_external_id_external_id
        """
        pass

    @route('attack_pattern.search')
    @search_entity(ATTACK_PATTERN_PREFIX)
    def _perform(self, *args, **kwargs):
        """
        https://private.intel.amp.cisco.com/index.html#!/Actor/get_ctia_actor_search
        """
        pass

    # Bundle

    @route('bundle.export.get')
    @search_entity('/ctia/bundle/export')
    def _perform(self, *args, **kwargs):
        """
        https://private.intel.amp.cisco.com/index.html#!/Bundle/get_ctia_bundle_export
        """
        pass

    @route('bundle.export.post')
    @create_entity('/ctia/bundle/export')
    def _perform(self, *args, **kwargs):
        """
        https://private.intel.amp.cisco.com/index.html#!/Bundle/post_ctia_bundle_export
        """
        pass

    @route('bundle.import')
    @create_entity('/ctia/bundle/import')
    def _perform(self, *args, **kwargs):
        """
        https://private.intel.amp.cisco.com/index.html#!/Bundle/post_ctia_bundle_import
        """
        pass
