import six

from .base import Request


class LoggedRequest(Request):
    """
    Logs every response of inner request.
    """

    MESSAGE_FORMAT = '{method} {url} {status_code} {reason_phrase}'

    def __init__(self, request, logger):
        self._request = request
        self._logger = logger

    def perform(self, method, url, **kwargs):
        try:
            response = self._request.perform(method, url, **kwargs)
        except Exception:
            self._log_error(method, url)
            raise

        if response.ok:  # 100 <= code < 400.
            self._log_success(method, url, response)
        else:  # 400 <= code < 600.
            self._log_error(method, url, response)

        return response

    @classmethod
    def _format(cls, method, url, response=None):
        return cls.MESSAGE_FORMAT.format(
            method=method.upper(),
            url=url,
            status_code=(
                '' if response is None else
                str(response.status_code)
            ),
            reason_phrase=(
                '' if response is None else
                six.moves.http_client.responses[response.status_code]
            ),
        ).rstrip()

    def _log_success(self, method, url, response):
        message = self._format(method, url, response)

        self._logger.info(message)

    def _log_error(self, method, url, response=None):
        message = self._format(method, url, response)

        if response is None:
            # The same as .error(), but also includes the current traceback.
            self._logger.exception(message)
        else:
            self._logger.error(message)
