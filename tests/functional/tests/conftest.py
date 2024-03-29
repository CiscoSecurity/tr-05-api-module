# coding: utf-8
"""Configurations for py.test runner"""
import pytest
from ctrlibrary.core.datafactory import gen_string
from ctrlibrary.threatresponse import token
from ctrlibrary.core import settings
from ctrlibrary.threatresponse.profile import update_org
from requests import HTTPError
from ctrlibrary.core.utils import delayed_return

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


@pytest.fixture(scope='function')
def update_org_name(module_headers):

    default_org_name = 'cisco'

    updated_org_name = update_org(payload={"name": "{0}".format(gen_string())},
                                  **{'headers': module_headers})['name']

    yield default_org_name, updated_org_name

    update_org(payload={"name": default_org_name},
               **{'headers': module_headers})


@pytest.fixture(scope='function')
def get_entity(module_tool_client):
    def _get_entity(entity_name):
        return getattr(module_tool_client.private_intel, entity_name)
    return _get_entity


@pytest.fixture(scope='function')
def get_post_response():
    def _get_response(entity_object, payload):
        post_tool_response = entity_object.post(
            payload=payload, params={'wait_for': 'true'})
        return post_tool_response
    return _get_response


@pytest.fixture(scope='function')
def get_entity_response(get_entity, get_post_response):
    global entity
    global entity_id
    entity = None
    entity_id = None

    def _get_entity_response(entity_name, payload, refs=None):
        if refs:
            payload.update(refs)
        global entity
        global entity_id
        entity = get_entity(entity_name)
        response = get_post_response(entity, payload)
        entity_id = response['id'].rpartition('/')[-1]
        return response
    yield _get_entity_response
    delayed_return(entity.delete(entity_id))
    with pytest.raises(HTTPError):
        entity.get(entity_id)
