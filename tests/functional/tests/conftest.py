# coding: utf-8
"""Configurations for py.test runner"""
import pytest
from ctrlibrary.core.datafactory import gen_string
from ctrlibrary.threatresponse import token
from ctrlibrary.core import settings
from ctrlibrary.threatresponse.profile import update_org
from threatresponse.client import ThreatResponse


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


@pytest.fixture(scope='function')
def update_org_name(module_headers):

    default_org_name = 'cisco'

    updated_org_name = update_org(payload={"name": "{0}".format(gen_string())},
                                  **{'headers': module_headers})['name']

    yield default_org_name, updated_org_name

    update_org(payload={"name": default_org_name},
               **{'headers': module_headers})
