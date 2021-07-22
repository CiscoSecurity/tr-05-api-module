from api.threatresponse.api import IntelAPI

from .assertions import *


def test_event_with_id_succeeds():
    request = invoke(IntelAPI, lambda api: api.event.history('12'))
    request.perform.assert_called_once_with(
        'GET',
        '/ctia/event/history/12'
    )
