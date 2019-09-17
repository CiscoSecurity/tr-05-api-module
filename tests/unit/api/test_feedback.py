from .assertions import *


def test_feedback_without_id_succeeds():
    assert_succeeds_with_get(
        lambda api, id_: api.feedback.get(),
        url='/ctia/feedback',
    )
