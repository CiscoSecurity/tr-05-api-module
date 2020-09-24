# coding: utf-8
"""Configurations for py.test runner"""
import random
import string

import pytest
from ctrlibrary.threatresponse import token
from ctrlibrary.core import settings
from threatresponse import ThreatResponse


def pytest_collection_modifyitems():
    if not settings.configured:
        settings.configure()
    return settings


@pytest.fixture(scope='module')
def module_token():
    return token.request_token(
        settings.server.ctr_client_id, settings.server.ctr_client_password)


@pytest.fixture(scope='module')
def module_headers(module_token):
    return {'Authorization': 'Bearer {}'.format(module_token)}


@pytest.fixture(scope='module')
def module_tool_client():
    return ThreatResponse(
        client_id=settings.server.ctr_client_id,
        client_password=settings.server.ctr_client_password
    )


@pytest.fixture(scope='module')
def module_tool_client_token(module_token):
    return ThreatResponse(
        token=module_token
    )


def gen_random_token():
    return ''.join(random.SystemRandom().choice(
        string.ascii_letters + string.digits) for _ in range(3437))
