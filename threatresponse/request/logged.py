import six

from .base import BaseRequest


class LoggedRequest(BaseRequest):

    def __init__(self, request, logger):
        self._request = request
        self._logger = logger

    def perform(self, method, url, **kwargs):
        message = '{} {}'.format(method.upper(), url)

        try:
            response = self._request.perform(method, url, **kwargs)
        except Exception:
            # The same as .error(), but also includes the current traceback
            self._logger.exception(message)
            raise

        else:
            code = response.status_code
            description = six.moves.http_client.responses[code]

            # Extend the message with the actual status code and description
            message = '{} {} {}'.format(message, code, description)

            if response.ok:  # 100 <= code < 400
                self._logger.info(message)
            else:  # 400 <= code < 600
                self._logger.error(message)

            return response
