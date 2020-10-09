from threatresponse.api.profile import ProfileAPI
from .assertions import *


def test_whoami_succeeds():
    request = invoke(ProfileAPI, lambda api: api.whoami())
    request.perform.assert_called_once_with(
        'GET',
        '/iroh/profile/whoami',
    )


def test_whoami_fails():
    request = invoke_with_failure(ProfileAPI, lambda api: api.whoami())
    request.perform.assert_called_once_with(
        'GET',
        '/iroh/profile/whoami',
    )


def test_org_get_succeeds():
    request = invoke(ProfileAPI, lambda api: api.org.get())
    request.perform.assert_called_once_with(
        'GET',
        '/iroh/profile/org',
    )


def test_org_get_fails():
    request = invoke_with_failure(ProfileAPI, lambda api: api.org.get())
    request.perform.assert_called_once_with(
        'GET',
        '/iroh/profile/org',
    )


def test_org_post_succeeds():
    request = invoke(ProfileAPI, lambda api: api.org.post(payload))
    request.perform.assert_called_once_with(
        'POST',
        '/iroh/profile/org',
        json=payload,
    )


def test_org_post_fails():
    request = invoke_with_failure(ProfileAPI, lambda api: api.org.post(payload))
    request.perform.assert_called_once_with(
        'POST',
        '/iroh/profile/org',
        json=payload
    )
