from six.moves.http_client import UNAUTHORIZED
from six.moves.urllib.parse import urljoin

from .base import Request
from ..urls import url_for


class ClientAuthorizedRequest(Request):
    """
    Provides authorization header for inner request.
    """

    def __init__(self, request, client_id,
                 client_password, region=None, environment=None):
        self._request = request
        self._client_id = client_id
        self._client_password = client_password

        self._token_url = urljoin(
            url_for(region, 'visibility', environment),
            '/iroh/oauth2/token'
        )

        self._token = self._request_token()

    def perform(self, method, url, **kwargs):
        headers = kwargs.pop('headers', {})

        response = self._perform(method, url, headers, **kwargs)

        if response.status_code == UNAUTHORIZED:
            # The token has already expired (most probably),
            # so regenerate it again and try one more time
            self._token = self._request_token()
            response = self._perform(method, url, headers, **kwargs)

        return response

    def _request_token(self):
        data = {'grant_type': 'client_credentials'}
        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                   'Accept': 'application/json'}
        auth = (self._client_id, self._client_password)  # HTTP Basic Auth

        response = self._request.post(self._token_url,
                                      data=data,
                                      headers=headers,
                                      auth=auth)

        response.raise_for_status()

        return response.json()['access_token']  # OK

    @property
    def _headers(self):
        return {'Authorization': 'Bearer {token}'.format(token=self._token)}

    def _perform(self, method, url, headers, **kwargs):
        headers.update(self._headers)
        kwargs['headers'] = headers
        return self._request.perform(method, url, **kwargs)


class TokenAuthorizedRequest(Request):
    """
    Provides authorization header for inner request.
    """

    def __init__(self, request, token, region=None, environment=None):
        self._request = request
        self._token = token
        self._check_url = urljoin(
            url_for(region, 'visibility', environment),
            '/iroh/iroh-enrich/settings',
        )
        self._check_token()

    def perform(self, method, url, **kwargs):
        headers = kwargs.pop('headers', {})
        response = self._perform(method, url, headers, **kwargs)
        return response

    def _check_token(self):
        headers = {'Accept': 'application/json'}
        headers.update(self._headers)

        response = self._perform('GET', self._check_url, headers)
        response.raise_for_status()

    @property
    def _headers(self):
        return {'Authorization': 'Bearer {token}'.format(token=self._token)}

    def _perform(self, method, url, headers, **kwargs):
        headers.update(self._headers)
        kwargs['headers'] = headers
        return self._request.perform(method, url, **kwargs)
