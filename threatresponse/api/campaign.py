from .routing import Router
from .base import API


class CampaignAPI(API):
    __router, route = Router.new()

    @route('campaign.get')
    def _perform(self, id_, **query):
        """
        https://private.intel.amp.cisco.com/index.html#!/Campaign/get_ctia_campaign_id
        """

        response = self._request.get(
                '/ctia/campaign/{}'.format(id_), params=query)
        response.raise_for_status()
        return response.json()

    @route('campaign.external_id')
    def _perform(self, id_, **query):
        """
        https://private.intel.amp.cisco.com/index.html#!/Campaign/get_ctia_campaign_id
        """

        response = self._request.get(
                '/ctia/campaign/external_id/{}'.format(id_), params=query)
        response.raise_for_status()
        return response.json()

    @route('campaign.search')
    def _perform(self, **query):
        """
        https://private.intel.amp.cisco.com/index.html#!/Campaign/get_ctia_campaign_id
        """

        response = self._request.get(
                '/ctia/campaign/search', params=query)
        response.raise_for_status()
        return response.json()

    @route('campaign.post')
    def _perform(self, payload):
        """
        https://private.intel.amp.cisco.com/index.html#!/Campaign/post_ctia_campaign
        """

        response = self._request.post('/ctia/campaign', json=payload)
        response.raise_for_status()
        return response.json()

    @route('campaign.delete')
    def _perform(self, id_):
        """
        https://private.intel.amp.cisco.com/index.html#!/Campaign/delete_ctia_campaign_id
        """

        response = self._request.delete(
            '/ctia/campaign/{}'.format(id_)
        )
        response.raise_for_status()
        return response.json()

    @route('campaign.put')
    def _perform(self, id_, payload):
        """
        https://private.intel.amp.cisco.com/index.html#!/Campaign/put_ctia_campaign_id
        """

        response = self._request.put(
            '/ctia/campaign/{}'.format(id_),
            json=payload,
        )
        response.raise_for_status()
        return response.json()
