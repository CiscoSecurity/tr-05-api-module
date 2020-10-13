from threatresponse.api.user_mgmt import UserMgmtAPI
from .assertions import *

test_user_id = "00000000-0000-0000-0000-000000000000"


def test_users_get_succeeds():
    request = invoke(
        UserMgmtAPI,
        lambda api: api.users.get(user_id=test_user_id)
    )
    request.perform.assert_called_once_with(
        'GET',
        '/iroh/user-mgmt/users/{}'.format(test_user_id),
    )


def test_users_get_fails():
    request = invoke_with_failure(
        UserMgmtAPI,
        lambda api: api.users.get(user_id=test_user_id)
    )
    request.perform.assert_called_once_with(
        'GET',
        '/iroh/user-mgmt/users/{}'.format(test_user_id),
    )


def test_users_post_succeeds():
    request = invoke(
        UserMgmtAPI,
        lambda api: api.users.post(user_id=test_user_id, payload=payload)
    )
    request.perform.assert_called_once_with(
        'POST',
        '/iroh/user-mgmt/users/{}'.format(test_user_id),
        json=payload,
    )


def test_users_post_fails():
    request = invoke_with_failure(
        UserMgmtAPI,
        lambda api: api.users.post(user_id=test_user_id, payload=payload)
    )
    request.perform.assert_called_once_with(
        'POST',
        '/iroh/user-mgmt/users/{}'.format(test_user_id),
        json=payload,
    )


def test_batch_users_succeeds():
    request = invoke(
        UserMgmtAPI,
        lambda api: api.batch.users(user_ids=[test_user_id])
    )
    request.perform.assert_called_once_with(
        'GET',
        f'/iroh/user-mgmt/batch/users',
        params={'id': ['00000000-0000-0000-0000-000000000000']}
    )


def test_batch_users_fails():
    request = invoke_with_failure(
        UserMgmtAPI,
        lambda api: api.batch.users(user_ids=[test_user_id])
    )
    request.perform.assert_called_once_with(
        'GET',
        f'/iroh/user-mgmt/batch/users',
        params={'id': ['00000000-0000-0000-0000-000000000000']}
    )


def test_search_users_succeeds():
    params = {
        "sort_by": "foo",
        "sort_order": "desc",
        "offset": "1",
        "search_after": ["bar"],
        "limit": "10",
    }
    request = invoke(
        UserMgmtAPI,
        lambda api: api.search.users(payload=payload, **params)
    )
    request.perform.assert_called_once_with(
        'POST',
        '/iroh/user-mgmt/search/users',
        json=payload,
        params=params
    )


def test_search_users_fails():
    request = invoke(
        UserMgmtAPI,
        lambda api: api.search.users(payload=payload)
    )
    request.perform.assert_called_once_with(
        'POST',
        '/iroh/user-mgmt/search/users',
        json=payload,
        params={
            "sort_by": None,
            "sort_order": None,
            "offset": None,
            "search_after": None,
            "limit": None,
        }
    )
