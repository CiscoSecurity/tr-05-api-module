from assertions import *


def test_event_with_id_succeeds():
    assert_succeeds_with_perform(
        lambda api, id_: api.event.history(12),
        url='/ctia/event/history/12',
        method='GET'
    )
