from api.threatresponse.api import IntelAPI

from .assertions import *


def test_feedback_without_id_succeeds():
    request = invoke(IntelAPI, lambda api: api.feedback.get())
    request.perform.assert_called_once_with(
        'GET',
        '/ctia/feedback'
    )
