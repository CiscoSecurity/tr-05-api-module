from .base import BaseRequest
from ..utils import raise_for_status


class AuthorizedRequest(BaseRequest):
    TOKEN_URL = 'https://visibility.amp.cisco.com/iroh/oauth2/token'
    UNATHORIZED_STATUS_CODE = 401

    def __init__(self, request, client_id, client_password):
        self._request = request
        self._client_id = client_id
        self._client_password = client_password

        self._token = self._generate_auth_token()

    def _generate_auth_token(self):
        data = {'grant_type': 'client_credentials'}
        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                   'Accept': 'application/json'}
        auth = (self._client_id, self._client_password)  # HTTP Basic Auth

        response = self._request.post(self.TOKEN_URL,
                                      data=data,
                                      headers=headers,
                                      auth=auth)

        raise_for_status(response)

        return response.json()['access_token']

    def _build_auth_headers(self):
        return {
            'Authorization': 'Bearer {}'.format(self._token),
        }

    def _perform(self, method, url, headers, **kwargs):
        headers.update(self._build_auth_headers())
        kwargs['headers'] = headers
        return self._request.perform(method, url, **kwargs)

    def perform(self, method, url, **kwargs):
        headers = kwargs.pop('headers', {})

        response = self._perform(method, url, headers, **kwargs)

        if response.status_code == self.UNATHORIZED_STATUS_CODE:
            # The token has already expired (most probably),
            # so regenerate it again and try one more time
            self._token = self._generate_auth_token()
            response = self._perform(method, url, headers, **kwargs)

        return response
