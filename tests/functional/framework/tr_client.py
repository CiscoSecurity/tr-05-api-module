from threatresponse import ThreatResponse


class PythonModuleClient:
    """
    Client to call module tr-05-api-module
    """
    def __init__(self, ctr_client_id, ctr_client_password):
        self.tr = ThreatResponse(
            client_id=ctr_client_id,
            client_password=ctr_client_password)

    def inspect(self, payload):
        """
        Call inspect endpoint for CTR

        return Observables
        """
        return self.tr.inspect.inspect({'content': payload})

    def enrich_observe_observables(self, observables):
        """
        Call enrich/observe endpoint for CTR
        """
        return self.tr.enrich.observe.observables(observables)

    def enrich_deliberate_observables(self, observables):
        """
        Call enrich/deliberate endpoint for CTR
        """
        return self.tr.enrich.deliberate.observables(observables)

    def enrich_refer_observables(self, observables):
        """
        Call enrich/refer endpoint for CTR
        """
        return self.tr.enrich.refer.observables(observables)

    def enrich_health(self):
        """
        Call enrich/health endpoint for CTR
        """
        return self.tr.enrich.health()
