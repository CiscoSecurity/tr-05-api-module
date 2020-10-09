from .base import API
from .routing import Router


class ProfileAPI(API):
    __router, route = Router.new()

    @route('whoami')
    def _perform(self, **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/profile/index.html#/Profile/get_iroh_profile_whoami
        """

        return self._get(
            '/iroh/profile/whoami',
            **kwargs
        )

    @route('org.get')
    def _perform(self, **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/profile/index.html#/Profile/get_iroh_profile_org
        """

        return self._get(
            '/iroh/profile/org',
            **kwargs
        )

    @route('org.post')
    def _perform(self, payload, **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/profile/index.html#/Profile/post_iroh_profile_org
        """

        return self._post(
            '/iroh/profile/org',
            json=payload,
            **kwargs
        )
