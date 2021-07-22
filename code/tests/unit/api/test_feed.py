from api.threatresponse.api import IntelAPI

from .assertions import *


def test_feed_view_with_id_succeeds():
    request = invoke(IntelAPI,
                     lambda api: api.feed.view(12, 'test'))
    request.perform.assert_called_once_with(
        'GET',
        '/ctia/feed/12/view',
        params={'s': 'test'}
    )


def test_feed_view_txt_with_id_succeeds():
    request = invoke(IntelAPI,
                     lambda api: api.feed.view.txt('12', 'test'),
                     response_type='text')
    request.perform.assert_called_once_with(
        'GET',
        '/ctia/feed/12/view.txt',
        params={'s': 'test'}
    )
