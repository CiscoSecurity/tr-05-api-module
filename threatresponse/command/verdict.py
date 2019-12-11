from .pipe import CachedPipe, Pipe


class Verdict:
    def __init__(self, tr):
        self._pipe = CachedPipe(
            Pipe(
                lambda observable: {'content': observable},
                tr.inspect.inspect,
                tr.enrich.deliberate.observables,
                lambda response: [doc.update({'module': data['module']}) or doc
                                  for data in response.get('data', {})
                                  for doc in data.get('data', {})
                                      .get('verdicts', {})
                                      .get('docs', [])]
            )
        )

    def perform(self, observable):
        return self._pipe(observable)
