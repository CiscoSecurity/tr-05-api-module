# coding: utf-8
"""Configurations for py.test runner"""
import pytest
from ctrlibrary.core.datafactory import gen_string
from ctrlibrary.threatresponse import token
from ctrlibrary.core import settings
from ctrlibrary.threatresponse.profile import update_org
from threatresponse import ThreatResponse
from requests import HTTPError
from tests.functional.tests.payloads import (
    SIGHTING_PAYLOAD,
    INCIDENT_PAYLOAD,
    RELATIONSHIP_PAYLOAD,
    JUDGEMENT_PAYLOAD,
    INDICATOR_PAYLOAD,
    ACTOR_PAYLOAD,
    ASSET_PAYLOAD,
    ASSET_MAPPING_PAYLOAD,
    ASSET_PROPERTIES_PAYLOAD,
    ATTACK_PATTERN_PAYLOAD,
    CAMPAIGN_PAYLOAD,
    COA_PAYLOAD,
    CASEBOOK_PAYLOAD,
    DATA_TABLE_PAYLOAD,
    FEED_PAYLOAD,
    FEEDBACK_PAYLOAD,
    IDENTITY_ASSERTION_PAYLOAD,
    INVESTIGATION_PAYLOAD,
    MALWARE_PAYLOAD,
    TARGET_RECORD_PAYLOAD,
    TOOL_PAYLOAD,
    VULNERABILITY_PAYLOAD,
    WEAKNESS_PAYLOAD
)
from ctrlibrary.core.utils import delayed_return


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


@pytest.fixture(scope='module')
def judgement(module_tool_client):
    return module_tool_client.private_intel.judgement


@pytest.fixture(scope='module')
def indicator(module_tool_client):
    return module_tool_client.private_intel.indicator


@pytest.fixture(scope='module')
def incident(module_tool_client):
    return module_tool_client.private_intel.incident


@pytest.fixture(scope='module')
def relationship(module_tool_client):
    return module_tool_client.private_intel.relationship


@pytest.fixture(scope='module')
def actor(module_tool_client):
    return module_tool_client.private_intel.actor


@pytest.fixture(scope='module')
def asset(module_tool_client):
    return module_tool_client.private_intel.asset


@pytest.fixture(scope='module')
def asset_mapping(module_tool_client):
    return module_tool_client.private_intel.asset_mapping


@pytest.fixture(scope='module')
def asset_properties(module_tool_client):
    return module_tool_client.private_intel.asset_properties


@pytest.fixture(scope='module')
def attack_pattern(module_tool_client):
    return module_tool_client.private_intel.attack_pattern


@pytest.fixture(scope='module')
def campaign(module_tool_client):
    return module_tool_client.private_intel.campaign


@pytest.fixture(scope='module')
def coa(module_tool_client):
    return module_tool_client.private_intel.coa


@pytest.fixture(scope='module')
def bulk(module_tool_client):
    return module_tool_client.private_intel.bulk


@pytest.fixture(scope='module')
def bundle(module_tool_client):
    return module_tool_client.private_intel.bundle


@pytest.fixture(scope='module')
def casebook(module_tool_client):
    return module_tool_client.private_intel.casebook


@pytest.fixture(scope='module')
def data_table(module_tool_client):
    return module_tool_client.private_intel.data_table


@pytest.fixture(scope='module')
def event(module_tool_client):
    return module_tool_client.private_intel.event


@pytest.fixture(scope='module')
def feed(module_tool_client):
    return module_tool_client.private_intel.feed


@pytest.fixture(scope='module')
def feedback(module_tool_client):
    return module_tool_client.private_intel.feedback


@pytest.fixture(scope='module')
def identity_assertion(module_tool_client):
    return module_tool_client.private_intel.identity_assertion


@pytest.fixture(scope='module')
def investigation(module_tool_client):
    return module_tool_client.private_intel.investigation


@pytest.fixture(scope='module')
def malware(module_tool_client):
    return module_tool_client.private_intel.malware


@pytest.fixture(scope='module')
def sighting(module_tool_client):
    return module_tool_client.private_intel.sighting


@pytest.fixture(scope='module')
def target_record(module_tool_client):
    return module_tool_client.private_intel.target_record


@pytest.fixture(scope='module')
def status(module_tool_client):
    return module_tool_client.private_intel.status


@pytest.fixture(scope='module')
def tool(module_tool_client):
    return module_tool_client.private_intel.tool


@pytest.fixture(scope='module')
def verdict(module_tool_client):
    return module_tool_client.private_intel.verdict


@pytest.fixture(scope='module')
def version(module_tool_client):
    return module_tool_client.private_intel.version


@pytest.fixture(scope='module')
def vulnerability(module_tool_client):
    return module_tool_client.private_intel.vulnerability


@pytest.fixture(scope='module')
def weakness(module_tool_client):
    return module_tool_client.private_intel.weakness


@pytest.fixture(scope='function')
def get_response():
    def _get_response(entity, payload):
        post_tool_response = entity.post(
            payload=payload, params={'wait_for': 'true'})
        return post_tool_response
    return _get_response


@pytest.fixture(scope='function')
def get_sighting_response(module_tool_client, get_response):
    sighting = module_tool_client.private_intel.sighting
    response = get_response(sighting, SIGHTING_PAYLOAD)
    yield response
    delayed_return(sighting.delete(response['id']))
    with pytest.raises(HTTPError):
        sighting.get(response['id'])


@pytest.fixture(scope='function')
def get_incident_response(incident, get_response):
    response = get_response(incident, INCIDENT_PAYLOAD)
    yield response
    delayed_return(incident.delete(response['id']))
    with pytest.raises(HTTPError):
        incident.get(response['id'])


@pytest.fixture(scope='function')
def get_relationship_response(module_tool_client, get_response, relationship):
    relationship_id = 0

    def _get_relationship_response(refs):
        nonlocal relationship_id
        RELATIONSHIP_PAYLOAD.update(refs)
        response = get_response(relationship, RELATIONSHIP_PAYLOAD)
        relationship_id = response['id'].rpartition('/')[-1]
        return response
    yield _get_relationship_response
    delayed_return(relationship.delete(relationship_id))
    with pytest.raises(HTTPError):
        relationship.get(relationship_id)


@pytest.fixture(scope='function')
def get_indicator_response(indicator, get_response):
    response = get_response(indicator, INDICATOR_PAYLOAD)
    yield response
    delayed_return(indicator.delete(response['id']))
    with pytest.raises(HTTPError):
        indicator.get(response['id'])


@pytest.fixture(scope='function')
def get_judgement_response(judgement, get_response):
    response = get_response(judgement, JUDGEMENT_PAYLOAD)
    yield response
    delayed_return(judgement.delete(response['id']))
    with pytest.raises(HTTPError):
        judgement.get(response['id'])


@pytest.fixture(scope='function')
def get_actor_response(actor, get_response):
    response = get_response(actor, ACTOR_PAYLOAD)
    yield response
    delayed_return(actor.delete(response['id']))
    with pytest.raises(HTTPError):
        actor.get(response['id'])


@pytest.fixture(scope='function')
def get_asset_response(asset, get_response):
    response = get_response(asset, ASSET_PAYLOAD)
    yield response
    delayed_return(asset.delete(response['id']))
    with pytest.raises(HTTPError):
        asset.get(response['id'])


@pytest.fixture(scope='function')
def get_asset_mapping_response(module_tool_client, get_response,
                               asset_mapping):
    asset_mapping_id = 0

    def _get_asset_mapping_response(refs):
        nonlocal asset_mapping_id
        ASSET_MAPPING_PAYLOAD.update(refs)
        response = get_response(asset_mapping, ASSET_MAPPING_PAYLOAD)
        asset_mapping_id = response['id'].rpartition('/')[-1]
        return response
    yield _get_asset_mapping_response
    delayed_return(asset_mapping.delete(asset_mapping_id))
    with pytest.raises(HTTPError):
        asset_mapping.get(asset_mapping_id)


@pytest.fixture(scope='function')
def get_asset_properties_response(
        module_tool_client, get_response, asset_properties):
    asset_properties_id = 0

    def _get_asset_properties_response(refs):
        nonlocal asset_properties_id
        ASSET_PROPERTIES_PAYLOAD.update(refs)
        response = get_response(asset_properties, ASSET_PROPERTIES_PAYLOAD)
        asset_properties_id = response['id'].rpartition('/')[-1]
        return response
    yield _get_asset_properties_response
    delayed_return(asset_properties.delete(asset_properties_id))
    with pytest.raises(HTTPError):
        asset_properties.get(asset_properties_id)


@pytest.fixture(scope='function')
def get_attack_pattern_response(attack_pattern, get_response):
    response = get_response(attack_pattern, ATTACK_PATTERN_PAYLOAD)
    yield response
    delayed_return(attack_pattern.delete(response['id']))
    with pytest.raises(HTTPError):
        attack_pattern.get(response['id'])


@pytest.fixture(scope='function')
def get_campaign_response(campaign, get_response):
    response = get_response(campaign, CAMPAIGN_PAYLOAD)
    yield response
    delayed_return(campaign.delete(response['id']))
    with pytest.raises(HTTPError):
        campaign.get(response['id'])


@pytest.fixture(scope='function')
def get_coa_response(coa, get_response):
    response = get_response(coa, COA_PAYLOAD)
    yield response
    delayed_return(coa.delete(response['id']))
    with pytest.raises(HTTPError):
        coa.get(response['id'])


@pytest.fixture(scope='function')
def get_casebook_response(casebook, get_response):
    response = get_response(casebook, CASEBOOK_PAYLOAD)
    yield response
    delayed_return(casebook.delete(response['id']))
    with pytest.raises(HTTPError):
        casebook.get(response['id'])


@pytest.fixture(scope='function')
def get_data_table_response(data_table, get_response):
    response = get_response(data_table, DATA_TABLE_PAYLOAD)
    yield response
    delayed_return(data_table.delete(response['id']))
    with pytest.raises(HTTPError):
        data_table.get(response['id'])


@pytest.fixture(scope='function')
def get_feed_response(module_tool_client, get_response, feed):
    feed_id = 0

    def _get_feed_response(refs):
        nonlocal feed_id
        ASSET_MAPPING_PAYLOAD.update(refs)
        response = get_response(feed, FEED_PAYLOAD)
        feed_id = response['id'].rpartition('/')[-1]
        return response
    yield _get_feed_response
    delayed_return(feed.delete(feed_id))
    with pytest.raises(HTTPError):
        feed.get(feed_id)


@pytest.fixture(scope='function')
def get_feedback_response(
        module_tool_client, get_response, feedback):
    feedback_id = 0

    def _get_asset_properties_response(refs):
        nonlocal feedback_id
        FEEDBACK_PAYLOAD.update(refs)
        response = get_response(feedback, FEEDBACK_PAYLOAD)
        feedback_id = response['id'].rpartition('/')[-1]
        return response
    yield _get_asset_properties_response
    delayed_return(feedback.delete(feedback_id))
    with pytest.raises(HTTPError):
        feedback.get(feedback_id)


@pytest.fixture(scope='function')
def get_identity_assertion_response(identity_assertion, get_response):
    response = get_response(identity_assertion, IDENTITY_ASSERTION_PAYLOAD)
    yield response
    delayed_return(identity_assertion.delete(response['id']))
    with pytest.raises(HTTPError):
        identity_assertion.get(response['id'])


@pytest.fixture(scope='function')
def get_investigation_response(investigation, get_response):
    response = get_response(investigation, INVESTIGATION_PAYLOAD)
    yield response
    delayed_return(investigation.delete(response['id']))
    with pytest.raises(HTTPError):
        investigation.get(response['id'])


@pytest.fixture(scope='function')
def get_malware_response(malware, get_response):
    response = get_response(malware, MALWARE_PAYLOAD)
    yield response
    delayed_return(malware.delete(response['id']))
    with pytest.raises(HTTPError):
        malware.get(response['id'])


@pytest.fixture(scope='function')
def get_target_record_response(target_record, get_response):
    response = get_response(target_record, TARGET_RECORD_PAYLOAD)
    yield response
    delayed_return(target_record.delete(response['id']))
    with pytest.raises(HTTPError):
        target_record.get(response['id'])


@pytest.fixture(scope='function')
def get_tool_response(tool, get_response):
    response = get_response(tool, TOOL_PAYLOAD)
    yield response
    delayed_return(tool.delete(response['id']))
    with pytest.raises(HTTPError):
        tool.get(response['id'])
    with pytest.raises(HTTPError):
        tool.delete(response['id'])


@pytest.fixture(scope='function')
def get_vulnerability_response(vulnerability, get_response):
    response = get_response(vulnerability, VULNERABILITY_PAYLOAD)
    yield response
    delayed_return(vulnerability.delete(response['id']))
    with pytest.raises(HTTPError):
        vulnerability.get(response['id'])


@pytest.fixture(scope='function')
def get_weakness_response(weakness, get_response):
    response = get_response(weakness, WEAKNESS_PAYLOAD)
    yield response
    delayed_return(weakness.delete(response['id']))
    with pytest.raises(HTTPError):
        weakness.get(response['id'])
