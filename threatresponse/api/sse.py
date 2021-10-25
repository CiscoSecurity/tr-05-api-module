from .base import API
from .routing import Router
from .. import urls


class SSEDeviceAPI(API):
    __router, route = Router.new()

    @route('get_all')
    def _perform(self, **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/iroh-sse/index.html#/SSE/get_iroh_iroh_sse_device
        """

        return self._get(
            '/iroh/iroh-sse/device',
            **kwargs
        )

    @route('get_by_id')
    def _perform(self, device_id, **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/iroh-sse/index.html#/SSE/get_iroh_iroh_sse_device__device_id_
        """

        return self._get(
            urls.join('/iroh/iroh-sse/device', device_id),
            **kwargs
        )

    @route('post')
    def _perform(self,
                 payload,
                 **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/iroh-sse/index.html#/SSE/post_iroh_iroh_sse_device
        """

        return self._post(
            '/iroh/iroh-sse/device',
            json=payload,
            **kwargs
        )

    @route('patch')
    def _perform(self,
                 device_id,
                 payload,
                 **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/iroh-sse/index.html#/SSE/patch_iroh_iroh_sse_device__device_id_
        """

        return self._patch(
            urls.join('/iroh/iroh-sse/device', device_id),
            json=payload,
            **kwargs
        )

    @route('token')
    def _perform(self,
                 device_id,
                 payload,
                 **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/iroh-sse/index.html#/SSE/post_iroh_iroh_sse_device__device_id__token
        """

        return self._post(
            urls.join('/iroh/iroh-sse/device', device_id, '/token'),
            json=payload,
            **kwargs
        )

    @route('re_token')
    def _perform(self,
                 device_id,
                 payload,
                 **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/iroh-sse/index.html#/SSE/post_iroh_iroh_sse_device__device_id__token
        """

        return self._post(
            urls.join('/iroh/iroh-sse/device', device_id, '/token'),
            json=payload,
            **kwargs
        )

    @route('api_proxy')
    def _perform(self,
                 device_id,
                 payload,
                 **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/iroh-sse/index.html#/SSE/post_iroh_iroh_sse_device__device_id__api_proxy
        """

        return self._post(
            urls.join('/iroh/iroh-sse/device', device_id, '/api-proxy'),
            json=payload,
            **kwargs
        )

    @route('delete')
    def _perform(self, device_id, **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/iroh-sse/index.html#/SSE/delete_iroh_iroh_sse_device__device_id_
        """

        return self._delete(
            urls.join('/iroh/iroh-sse/device', device_id),
            **kwargs
        )


class SSETenantAPI(API):
    __router, route = Router.new()

    @route('get_token')
    def _perform(self, **kwargs):
        """
        https://visibility.amp.cisco.com/iroh/iroh-sse/index.html#/SSE/get_iroh_iroh_sse_tenant_token
        """

        return self._get(
            '/iroh/iroh-sse/tenant/token',
            **kwargs
        )
