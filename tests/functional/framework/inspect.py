from ctrlibrary.core.decorators import to_json
from tests.functional.framework import base
from tests.functional.framework.endpoints import (
    INSPECT_URL,
    PARENT_INSPECT_URL,
)


@to_json
def inspect(payload, **kwargs):
    """Perform POST call to end point using inspect statement"""
    return base.ctr_post_data(
        payload=payload,
        section_url=PARENT_INSPECT_URL,
        target_url=INSPECT_URL,
        **kwargs
    )
