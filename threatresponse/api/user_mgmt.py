from .base import API
from .routing import Router
from .. import urls


class UserMgmtAPI(API):
    __router, route = Router.new()

    @route('users.get')
    def _perform(self, user_id, **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/user-mgmt/index.html#/User/get_iroh_user_mgmt_users__user_id_
        """

        return self._get(
            urls.join('/iroh/user-mgmt/users', user_id),
            **kwargs
        )

    @route('users.post')
    def _perform(self,
                 user_id,
                 payload,
                 **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/user-mgmt/index.html#/User/post_iroh_user_mgmt_users__user_id_
        """

        return self._post(
            urls.join('/iroh/user-mgmt/users', user_id),
            json=payload,
            **kwargs
        )

    @route('batch.users')
    def _perform(self, user_ids, **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/user-mgmt/index.html#/User/get_iroh_user_mgmt_batch_users
        """

        return self._get(
            '/iroh/user-mgmt/batch/users',
            params={'id': user_ids},
            **kwargs
        )

    @route('search.users')
    def _perform(self,
                 payload,
                 sort_by=None,
                 sort_order=None,
                 offset=None,
                 search_after=None,
                 limit=None,
                 **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/user-mgmt/index.html#/User/post_iroh_user_mgmt_search_users
        """

        query = {
            'sort_by': sort_by,
            'sort_order': sort_order,
            'offset': offset,
            'search_after': search_after,
            'limit': limit
        }

        return self._post(
            '/iroh/user-mgmt/search/users',
            json=payload,
            params=query,
            **kwargs
        )
