import abc
import six


class Request(six.with_metaclass(abc.ABCMeta, object)):

    @abc.abstractmethod
    def perform(self, method, url, **kwargs):
        pass

    def get(self, url, **kwargs):
        return self.perform('GET', url, **kwargs)

    def post(self, url, **kwargs):
        return self.perform('POST', url, **kwargs)

    def put(self, url, **kwargs):
        return self.perform('PUT', url, **kwargs)

    def delete(self, url, **kwargs):
        return self.perform('DELETE', url, **kwargs)
