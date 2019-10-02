from .assertions import *


def test_feedback_without_id_succeeds():
    request = invoke(lambda api: api.feedback.get())
    request.get.assert_called_once_with(
        '/ctia/feedback', params={})
