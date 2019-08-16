from ctrlibrary.core.decorators import to_json
from tests.functional.framework import base
from tests.functional.framework.endpoints import (
    ENRICH_DELIBERATE_OBSERVABLES,
    ENRICH_OBSERVE_OBSERVABLES,
    ENRICH_REFER_OBSERVABLES,
    PARENT_ENRICH_URL,
)


@to_json
def enrich_deliberate_observables(payload, **kwargs):
    """Perform POST call to end point using enrich deliberate observables
    statement
    """
    return base.ctr_post_data(
        payload=payload,
        section_url=PARENT_ENRICH_URL,
        target_url=ENRICH_DELIBERATE_OBSERVABLES,
        **kwargs
    )


@to_json
def enrich_observe_observables(payload, **kwargs):
    """Perform POST call to end point using enrich observe observables
    statement
    """
    return base.ctr_post_data(
        payload=payload,
        section_url=PARENT_ENRICH_URL,
        target_url=ENRICH_OBSERVE_OBSERVABLES,
        **kwargs
    )


@to_json
def enrich_refer_observables(payload, **kwargs):
    """Perform POST call to end point using enrich refer observables statement
    """
    return base.ctr_post_data(
        payload=payload,
        section_url=PARENT_ENRICH_URL,
        target_url=ENRICH_REFER_OBSERVABLES,
        **kwargs
    )
