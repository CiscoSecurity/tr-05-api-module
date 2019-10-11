from threatresponse.api import IntelAPI

from .assertions import *


def test_casebook_observable_with_id_succeeds():
    request = invoke(IntelAPI, lambda api: api.casebook.observables(12, payload))
    request.perform.assert_called_once_with(
        'POST',
        '/ctia/casebook/12/observables',
        json=payload
    )


def test_casebook_text_with_id_succeeds():
    request = invoke(IntelAPI, lambda api: api.casebook.texts(12, payload))
    request.perform.assert_called_once_with(
        'POST',
        '/ctia/casebook/12/texts',
        json=payload
    )


def test_casebook_bulk_with_id_succeeds():
    request = invoke(IntelAPI, lambda api: api.casebook.bundle(12, payload))
    request.perform.assert_called_once_with(
        'POST',
        '/ctia/casebook/12/bundle',
        json=payload
    )
