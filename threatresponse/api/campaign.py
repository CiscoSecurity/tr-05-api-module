from .routing import Router
from .base import API
from urllib import urlencode


class CampaignAPI(API):
    __router, route = Router.new()

    @route('campaign_by_id')
    def _perform(self, id_, fields=None):
        """
        https://private.intel.amp.cisco.com/index.html#!/Campaign/get_ctia_campaign_id
        """
        if fields:
            response = self._request.get(
                '/ctia/campaign/{}'.format(id_) + '?' + ''.join('fields='+field+'&' for field in fields))
        else:
            response = self._request.get(
                '/ctia/campaign/{}'.format(id_))
        response.raise_for_status()
        return response.json()

    @route('campaign.external_id')
    def _perform(self, id_, fields=None, query=None):
        """
        https://private.intel.amp.cisco.com/index.html#!/Campaign/get_ctia_campaign_external_id_external_id
        """
        if fields and query:
            response = self._request.get(
                '/ctia/campaign/external_id/{}'.format(id_) + '?'
                + ''.join('fields='+field+'&' for field in fields) +
                urlencode(query))
        elif fields:
            response = self._request.get(
                '/ctia/campaign/external_id/{}'.format(id_)+ '?'
                + ''.join('fields='+field+'&' for field in fields))
        elif query:
            response = self._request.get(
                '/ctia/campaign/external_id/{}'.format(id_) + '?' + urlencode(query))
        else:
            response = self._request.get(
                '/ctia/campaign/external_id/{}'.format(id_)
            )
        response.raise_for_status()
        return response.json()

    @route('campaign.search')
    def _perform(self, query):
        """
        !!!https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Refer/post_iroh_iroh_enrich_refer_observables
        """
        if query:
            response = self._request.get(
                '/ctia/campaign/search',
                params=query
            )
        else:
            response = self._request.get(
                '/ctia/campaign/search',
            )
        response.raise_for_status()
        return response.json()

    @route('campaign')
    def _perform(self):
        """
        !!!https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Health/post_iroh_iroh_enrich_health
        """

        response = self._request.post('/ctia/campaign')
        response.raise_for_status()
        return response.json()

    @route('delete_campaign')
    def _perform(self, id_):
        """
        !!!https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Deliberate/post_iroh_iroh_enrich_deliberate_observables
        """

        response = self._request.delete(
            '/ctia/campaign/{}'.format(id_)
        )
        response.raise_for_status()
        return response.json()

    @route('campaign_update')
    def _perform(self, id_, payload):
        """
        !!!https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Refer/post_iroh_iroh_enrich_refer_observables
        """

        response = self._request.put(
            '/ctia/campaign/{}'.format(id_),
            json=payload,
        )
        response.raise_for_status()
        return response.json()

