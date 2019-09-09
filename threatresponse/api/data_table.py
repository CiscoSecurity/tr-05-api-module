from .routing import Router
from .base import API


class DataTableAPI(API):
    __router, route = Router.new()

    @route('data_table.get')
    def _perform(self, id_, **query):
        """
        https://private.intel.amp.cisco.com/index.html#!/DataTable/get_ctia_data_table_id
        """

        response = self._request.get(
                '/ctia/data_table/{}'.format(id_), params=query)
        response.raise_for_status()
        return response.json()

    @route('data_table.external_id')
    def _perform(self, id_, **query):
        """
        https://private.intel.amp.cisco.com/index.html#!/DataTable/get_ctia_data_table_external_id_external_id
        """

        response = self._request.get(
                '/ctia/data_table/external_id/{}'.format(id_), params=query)
        response.raise_for_status()
        return response.json()

    @route('data_table.post')
    def _perform(self, payload):
        """
        https://private.intel.amp.cisco.com/index.html#!/DataTable/post_ctia_data_table
        """

        response = self._request.post('/ctia/data_table', json=payload)
        response.raise_for_status()
        return response.json()

    @route('data_table.delete')
    def _perform(self, id_):
        """
        https://private.intel.amp.cisco.com/index.html#!/DataTable/delete_ctia_data_table_id
        """

        response = self._request.delete(
            '/ctia/data_table/{}'.format(id_)
        )
        response.raise_for_status()
        return response.json()