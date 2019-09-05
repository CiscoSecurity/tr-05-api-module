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
                '/ctia/campaign/{}'.format(id_) + '?' + array_for_url(fields))
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
                + array_for_url(fields) +
                urlencode(query))
        elif fields:
            response = self._request.get(
                '/ctia/campaign/external_id/{}'.format(id_)+ '?'
                + array_for_url(fields))
        elif query:
            response = self._request.get(
                '/ctia/campaign/external_id/{}'.format(id_) + '?' + urlencode(query))
        else:
            response = self._request.get(
                '/ctia/campaign/external_id/{}'.format(id_))
        response.raise_for_status()
        return response.json()

    @route('campaign.search')
    def _perform(self, query, fields=None, search_after=None):
        """
        !!!https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html#!/Refer/post_iroh_iroh_enrich_refer_observables
        """
        if fields and search_after:
            response = self._request.get(
                '/ctia/campaign/search' + '?'
                + array_for_url(fields) + '?'
                + array_for_url(search_after) + '?'
                + urlencode(query))
        elif fields:
            response = self._request.get(
                '/ctia/campaign/search' + '?'
                + array_for_url(fields) + '?'
                + urlencode(query))
        elif search_after:
            response = self._request.get(
                '/ctia/campaign/search' + '?'
                + array_for_url(search_after) + '?'
                + urlencode(query))
        else:
            response = self._request.get(
                '/ctia/campaign/search' + '?'
                + urlencode(query))
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

def array_for_url(array):
    return ''.join('fields=' + element + '&' for element in array)