from .assertions import *


def test_casebook_observable_with_id_succeeds():
    assert_succeeds_with_perform(
        lambda api, id_, payload: api.casebook.observables(12, payload),
        url='/ctia/casebook/12/observables',
        method='POST',
        payload={"zip": "zap"}
    )


def test_casebook_text_with_id_succeeds():
    assert_succeeds_with_perform(
        lambda api, id_, payload: api.casebook.texts(12, payload),
        url='/ctia/casebook/12/texts',
        method='POST',
        payload={"zip": "zap"}
    )


def test_casebook_bulk_with_id_succeeds():
    assert_succeeds_with_perform(
        lambda api, id_, payload: api.casebook.bundle(12, payload),
        url='/ctia/casebook/12/bundle',
        method='POST',
        payload={"zip": "zap"}
    )