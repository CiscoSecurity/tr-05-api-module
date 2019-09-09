from .routing import Router
from .base import API


class COAAPI(API):
    __router, route = Router.new()

    @route('coa.get')
    def _perform(self, id_, **query):
        """
        https://private.intel.amp.cisco.com/index.html#!/COA/get_ctia_coa_id
        """

        response = self._request.get(
                '/ctia/coa/{}'.format(id_), params=query)
        response.raise_for_status()
        return response.json()

    @route('coa.external_id')
    def _perform(self, id_, **query):
        """
        https://private.intel.amp.cisco.com/index.html#!/COA/get_ctia_coa_external_id_external_id
        """

        response = self._request.get(
                '/ctia/coa/external_id/{}'.format(id_), params=query)
        response.raise_for_status()
        return response.json()

    @route('coa.search')
    def _perform(self, **query):
        """
        https://private.intel.amp.cisco.com/index.html#!/COA/get_ctia_coa_search
        """

        response = self._request.get(
                '/ctia/coa/search', params=query)
        response.raise_for_status()
        return response.json()

    @route('coa.post')
    def _perform(self, payload):
        """
        https://private.intel.amp.cisco.com/index.html#!/COA/post_ctia_coa
        """

        response = self._request.post('/ctia/coa', json=payload)
        response.raise_for_status()
        return response.json()

    @route('coa.delete')
    def _perform(self, id_):
        """
        https://private.intel.amp.cisco.com/index.html#!/COA/delete_ctia_coa_id
        """

        response = self._request.delete(
            '/ctia/coa/{}'.format(id_)
        )
        response.raise_for_status()
        return response.json()

    @route('coa.put')
    def _perform(self, id_, payload):
        """
        https://private.intel.amp.cisco.com/index.html#!/COA/put_ctia_coa_id
        """

        response = self._request.put(
            '/ctia/coa/{}'.format(id_),
            json=payload,
        )
        response.raise_for_status()
        return response.json()
