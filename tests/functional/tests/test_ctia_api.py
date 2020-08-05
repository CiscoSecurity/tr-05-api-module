import pytest
import random
from requests import HTTPError

from ctrlibrary.core import settings
from ctrlibrary.core.datafactory import gen_ip
from ctrlibrary.core.utils import delayed_return
from ctrlibrary.threatresponse import token
from ctrlibrary.ctia.base import ctia_get_data
from ctrlibrary.ctia.endpoints import (
    ACTOR,
    ATTACK_PATTERN,
    CAMPAIGN,
    CASEBOOK,
    COA,
    DATA_TABLE,
    FEED,
    FEEDBACK,
    IDENTITY_ASSERTION,
    INCIDENT,
    INDICATOR,
    INVESTIGATION,
    JUDGEMENT,
    MALWARE,
    RELATIONSHIP,
    SIGHTING,
    TOOL,
    VERDICT,
    VULNERABILITY,
    WEAKNESS,
)
from threatresponse import ThreatResponse


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


SERVER_VERSION = '1.0.16'


def test_python_module_ctia_positive_actor(module_headers, module_tool_client):
    """Perform testing for actor entity of custom threat intelligence python
    module

    ID: CCTRI-160-1f5de8b8-11a8-4110-a982-8547a2202789

    Steps:

        1. Send POST request to create new actor entity using custom python
            module
        2. Send GET request using custom python module to read just created
            entity back.
        3. Send same GET request, but using direct access to the server
        4. Compare results
        5. Update actor entity using custom python module
        6. Repeat GET request using python module and validate that entity was
            updated
        7. Delete entity from the system

    Expectedresults: Actor entity can be created, fetched, updated and
        deleted using custom python module. Data stored in the entity is
        the same no matter you access it directly or using our tool

    Importance: Critical
    """
    actor = module_tool_client.private_intel.actor
    payload = {
        'actor_type': 'Hacker',
        'confidence': 'High',
        'schema_version': SERVER_VERSION,
        'source': 'a source',
        'type': 'actor',
    }
    # Create new entity using provided payload
    post_tool_response = actor.post(payload=payload,
                                    params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'actor_type',
            'confidence',
            'schema_version',
            'source',
            'type'
        ]
    }
    assert values == payload
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_tool_response = actor.get(entity_id)
    get_direct_response = ctia_get_data(
        target_url=ACTOR,
        entity_id=entity_id,
        **{'headers': module_headers}
    ).json()
    assert get_tool_response == get_direct_response
    # Update entity values
    put_tool_response = delayed_return(
        actor.put(
            id_=entity_id,
            payload={'source': 'new source point', 'actor_type': 'Hacker'}
        )
    )
    assert put_tool_response['source'] == 'new source point'
    get_tool_response = actor.get(entity_id)
    assert get_tool_response['source'] == 'new source point'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(actor.delete(entity_id))
    with pytest.raises(HTTPError):
        actor.get(entity_id)


def test_python_module_ctia_positive_attack_pattern(
        module_headers, module_tool_client):
    """Perform testing for attack pattern entity of custom threat intelligence
    python module

    ID: CCTRI-160-86d8f8ef-fbf4-4bf4-88c2-a57f4fe6b866

    Steps:

        1. Send POST request to create new attack pattern entity using custom
            python module
        2. Send GET request using custom python module to read just created
            entity back.
        3. Send same GET request, but using direct access to the server
        4. Compare results
        5. Update attack pattern entity using custom python module
        6. Repeat GET request using python module and validate that entity was
            updated
        7. Delete entity from the system

    Expectedresults: Attack pattern entity can be created, fetched, updated and
        deleted using custom python module. Data stored in the entity is
        the same no matter you access it directly or using our tool

    Importance: Critical
    """
    attack_pattern = module_tool_client.private_intel.attack_pattern
    payload = {
        'description': (
            'A bootkit is a malware variant that modifies the boot sectors of'
            ' a hard drive'
        ),
        'name': 'Bootkit',
        'schema_version': SERVER_VERSION,
        'type': 'attack-pattern'
    }
    # Create new entity using provided payload
    post_tool_response = attack_pattern.post(payload=payload,
                                             params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'description',
            'name',
            'schema_version',
            'type'
        ]
    }
    assert values == payload
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_tool_response = attack_pattern.get(entity_id)
    get_direct_response = ctia_get_data(
        target_url=ATTACK_PATTERN,
        entity_id=entity_id,
        **{'headers': module_headers}
    ).json()
    assert get_tool_response == get_direct_response
    # Update entity values
    put_tool_response = delayed_return(
        attack_pattern.put(
            id_=entity_id,
            payload={
                'name': 'Worm',
                'description': (
                    'A standalone malware that replicates itself in order to'
                    ' spread to other computers'
                )
            }
        )
    )
    assert put_tool_response['name'] == 'Worm'
    get_tool_response = attack_pattern.get(entity_id)
    assert get_tool_response['name'] == 'Worm'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(attack_pattern.delete(entity_id))
    with pytest.raises(HTTPError):
        attack_pattern.get(entity_id)


def test_python_module_ctia_positive_bulk(module_headers, module_tool_client):
    """Perform testing for bulk functionality of custom threat intelligence
    python module

    ID: CCTRI-165-7db40d60-9767-47d2-98a5-e734562fa9f1

    Steps:

        1. Send POST request to create one campaign entity and one coa entity
            in a bulk using custom python module
        2. Send GET request using custom python module and bulk functionality
            to read just created entities back.
        3. Validate response
        4. Send GET request, but using usual single entity endpoint with custom
            python module
        5. Send same GET request, but with direct access to the server
        6. Compare results

    Expectedresults: Bulk functionality works properly and some entities can be
        created in the same time using custom python module

    Importance: Critical
    """
    bulk = module_tool_client.private_intel.bulk
    campaign = module_tool_client.private_intel.campaign
    campaign_payload = {
        'campaign_type': 'Critical',
        'confidence': 'Medium',
        'type': 'campaign',
        'schema_version': SERVER_VERSION
    }
    coa_payload = {
        'description': 'COA entity we use for bulk testing',
        'coa_type': 'Diplomatic Actions',
        'type': 'coa',
        'schema_version': SERVER_VERSION
    }
    # Create Campaign and COA entities in bulk
    post_tool_response = delayed_return(
        bulk.post({
            "coas": [coa_payload], "campaigns": [campaign_payload]},
        )
    )
    assert len(post_tool_response['campaigns']) > 0
    assert len(post_tool_response['coas']) > 0
    campaign_entity_id = post_tool_response['campaigns'][0].rpartition('/')[-1]
    # Verify that GET request using bulk functionality return valid data
    get_tool_response = bulk.get(params={'campaigns': [campaign_entity_id]})
    values = {
        key: get_tool_response['campaigns'][0][key] for key in [
            'campaign_type',
            'confidence',
            'type',
            'schema_version'
        ]
    }
    assert values == campaign_payload
    # Validate that GET request return same data for direct access and access
    # through custom python module for entity that was created using bulk
    # functionality
    get_tool_response = campaign.get(campaign_entity_id)
    get_direct_response = ctia_get_data(
        target_url=CAMPAIGN,
        entity_id=campaign_entity_id,
        **{'headers': module_headers}
    ).json()
    assert get_tool_response == get_direct_response


def test_python_module_ctia_positive_bundle(module_tool_client):
    """Perform testing for bundle functionality of custom threat intelligence
    python module

    ID: CCTRI-172-f483fa82-f308-4606-9045-ffc2dc8b41f0

    Steps:

        1. Send POST request to create one incident entity to be used for
            bundle functionality
        2. Send POST request to create one indicator entity to be used for
            bundle functionality
        3. Send POST request to export data using bundle functionality
        4. Send POST request to import data using bundle functionality

    Expectedresults: Bundle functionality works properly and some entities can
        be imported or exported using custom python module

    Importance: Critical
    """
    # Prepare data for incident
    incident = module_tool_client.private_intel.incident
    payload = {
        'confidence': 'Low',
        'incident_time': {
            'opened': "2014-01-11T00:40:48.212Z"
        },
        'status': 'New',
        'type': 'incident',
        'schema_version': SERVER_VERSION
    }
    # Create new incident using provided payload
    incident_post_response = incident.post(payload=payload,
                                           params={'wait_for': 'true'})
    # Prepare data for indicator
    indicator = module_tool_client.private_intel.indicator
    payload = {
        'producer': 'producer',
        'schema_version': SERVER_VERSION,
        'type': 'indicator',
        'revision': 0
    }
    # Create new indicator using provided payload
    indicator_post_response = indicator.post(payload=payload,
                                             params={'wait_for': 'true'})
    # Use created entities for bundle
    bundle = module_tool_client.private_intel.bundle
    payload = {
        'ids': [
            incident_post_response['id'],
            indicator_post_response['id']
        ]
    }
    # Validate export endpoint
    post_tool_response = bundle.export.post(payload=payload)
    assert post_tool_response['type'] == 'bundle'
    assert post_tool_response['source'] == 'ctia'
    assert post_tool_response['incidents'][0]['id'] == (
        incident_post_response['id']
    )
    assert post_tool_response[
        'indicators'][0]['id'] == indicator_post_response['id']
    # Validate import endpoint
    payload = {
        'schema_version': SERVER_VERSION,
        'type': 'bundle',
        'source': 'random source',
    }
    post_tool_response = bundle.import_.post(payload=payload)
    assert post_tool_response


def test_python_module_ctia_positive_campaign(
        module_headers, module_tool_client):
    """Perform testing for campaign entity of custom threat intelligence python
    module

    ID: CCTRI-161-0bb11c77-5b26-43cb-841a-b18f0fa0563c

    Steps:

        1. Send POST request to create new campaign entity using custom python
            module
        2. Send GET request using custom python module to read just created
            entity back.
        3. Send same GET request, but using direct access to the server
        4. Compare results
        5. Update campaign entity using custom python module
        6. Repeat GET request using python module and validate that entity was
            updated
        7. Send SEARCH request using custom python module to find entity and
            validate proper values are returned
        8. Delete entity from the system

    Expectedresults: Campaign entity can be created, fetched, updated, searched
        and deleted using custom python module. Data stored in the entity is
        the same no matter you access it directly or using our tool

    Importance: Critical
    """
    campaign = module_tool_client.private_intel.campaign
    payload = {
        'title': 'Demo campaign',
        'campaign_type': 'Critical',
        'confidence': 'Medium',
        'type': 'campaign',
        'schema_version': SERVER_VERSION
    }
    # Create new entity using provided payload
    post_tool_response = campaign.post(payload=payload,
                                       params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'title',
            'campaign_type',
            'confidence',
            'type',
            'schema_version'
        ]
    }
    assert values == payload
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_tool_response = campaign.get(entity_id)
    get_direct_response = ctia_get_data(
        target_url=CAMPAIGN,
        entity_id=entity_id,
        **{'headers': module_headers}
    ).json()
    assert get_tool_response == get_direct_response
    # Update entity values
    put_tool_response = delayed_return(
        campaign.put(
            id_=entity_id,
            payload={'title': 'New demo campaign', 'campaign_type': 'Critical'}
        )
    )
    assert put_tool_response['title'] == 'New demo campaign'
    get_tool_response = campaign.get(entity_id)
    assert get_tool_response['title'] == 'New demo campaign'
    # Search for campaign by entity id
    search_tool_response = campaign.search(params={
        'query': 'id:*{}'.format(entity_id)})
    # We got exactly one entry for provided unique entity id
    assert len(search_tool_response) == 1
    assert search_tool_response[0]['title'] == 'New demo campaign'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(campaign.delete(entity_id))
    with pytest.raises(HTTPError):
        campaign.get(entity_id)


def test_python_module_ctia_positive_casebook(
        module_headers, module_tool_client):
    """Perform testing for casebook entity of custom threat intelligence python
    module

    ID: CCTRI-165-d6fb1e17-324f-4de8-a388-2d6ab33dd071

    Steps:

        1. Send POST request to create new casebook entity using custom python
            module
        2. Send GET request using custom python module to read just created
            entity back.
        3. Send same GET request, but using direct access to the server
        4. Compare results
        5. Add new observable entity to the casebook
        6. Send GET request to validate that observable was actually added
        7. Update casebook entity using custom python module
        8. Repeat GET request using python module and validate that entity was
            updated
        9. Delete entity from the system

    Expectedresults: Casebook entity can be created, fetched, updated and
        deleted using custom python module. Data stored in the entity is
        the same no matter you access it directly or using our tool

    Importance: Critical
    """
    casebook = module_tool_client.private_intel.casebook
    observable = [{'value': 'instanbul.com', 'type': 'domain'}]
    payload = {
        'type': 'casebook',
        'title': 'Case September 24, 2019 2:34 PM',
        'short_description': 'New Casebook',
        'description': 'New Casebook for malicious tickets',
        'observables': [],
        'timestamp': '2019-09-24T11:34:18.000Z'
    }
    # Create new entity using provided payload
    post_tool_response = casebook.post(payload=payload,
                                       params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'type',
            'title',
            'short_description',
            'description',
            'observables',
            'timestamp'
        ]
    }
    assert values == payload
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_tool_response = casebook.get(entity_id)
    get_direct_response = ctia_get_data(
        target_url=CASEBOOK,
        entity_id=entity_id,
        **{'headers': module_headers}
    ).json()
    assert get_tool_response == get_direct_response
    # Add one observable to casebook using special endpoint for this purpose
    delayed_return(
        casebook.observables(
            entity_id,
            {
                'operation': 'add',
                'observables': observable
            }
        )
    )
    get_tool_response = casebook.get(entity_id)
    assert get_tool_response['observables'] == observable
    # Update entity values
    put_tool_response = delayed_return(
        casebook.put(
            id_=entity_id,
            payload={'short_description': 'Updated description'}
        )
    )
    assert put_tool_response['short_description'] == 'Updated description'
    get_tool_response = casebook.get(entity_id)
    assert get_tool_response['short_description'] == 'Updated description'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(casebook.delete(entity_id))
    with pytest.raises(HTTPError):
        casebook.get(entity_id)


def test_python_module_ctia_positive_coa(module_headers, module_tool_client):
    """Perform testing for coa entity of custom threat intelligence python
    module

    ID: CCTRI-161-03b73a5e-b919-4e94-8828-c388e1ba211e

    Steps:

        1. Send POST request to create new coa entity using custom python
            module
        2. Send GET request using custom python module to read just created
          entity back.
        3. Send same GET request, but using direct access to the server
        4. Compare results
        5. Update coa entity using custom python module
        6. Repeat GET request using python module and validate that entity was
            updated
        7. Delete entity from the system

    Expectedresults: COA entity can be created, fetched, updated and
        deleted using custom python module. Data stored in the entity is
        the same no matter you access it directly or using our tool

    Importance: Critical
    """
    coa = module_tool_client.private_intel.coa
    payload = {
        'description': 'COA entity we use for testing',
        'structured_coa_type': 'openc2',
        'coa_type': 'Diplomatic Actions',
        'type': 'coa',
        'schema_version': SERVER_VERSION
    }
    # Create new entity using provided payload
    post_tool_response = coa.post(payload=payload,
                                  params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'description',
            'structured_coa_type',
            'coa_type',
            'type',
            'schema_version'
        ]
    }
    assert values == payload
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_tool_response = coa.get(entity_id)
    get_direct_response = ctia_get_data(
        target_url=COA,
        entity_id=entity_id,
        **{'headers': module_headers}
    ).json()
    assert get_tool_response == get_direct_response
    # Update entity values
    put_tool_response = delayed_return(
        coa.put(
            id_=entity_id,
            payload={'description': 'New COA description'}
        )
    )
    assert put_tool_response['description'] == 'New COA description'
    get_tool_response = coa.get(entity_id)
    assert get_tool_response['description'] == 'New COA description'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(coa.delete(entity_id))
    with pytest.raises(HTTPError):
        coa.get(entity_id)


def test_python_module_ctia_positive_data_table(
        module_headers, module_tool_client):
    """Perform testing for data table entity of custom threat intelligence
    python module

    ID: CCTRI-161-c89f865b-c070-446f-a052-8fae73c4d564

    Steps:

        1. Send POST request to create new data table entity using custom
            python module
        2. Send GET request using custom python module to read just created
            entity back.
        3. Send same GET request, but using direct access to the server
        4. Compare results
        5. Delete entity from the system

    Expectedresults: Data table entity can be created, fetched and deleted
        using custom python module. Data stored in the entity is the same no
        matter you access it directly or using our tool

    Importance: Critical
    """
    data_table = module_tool_client.private_intel.data_table
    payload = {
        'schema_version': SERVER_VERSION,
        'type': 'data-table',
        'columns': [{'name': 'column', 'type': 'string'}],
        'rows': [[{}]]
    }
    # Create new entity using provided payload
    post_tool_response = data_table.post(payload=payload,
                                         params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'columns',
            'rows',
            'type',
            'schema_version'
        ]
    }
    assert values == payload
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_tool_response = data_table.get(entity_id)
    get_direct_response = ctia_get_data(
        target_url=DATA_TABLE,
        entity_id=entity_id,
        **{'headers': module_headers}
    ).json()
    assert get_tool_response == get_direct_response
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(data_table.delete(entity_id))
    with pytest.raises(HTTPError):
        data_table.get(entity_id)


def test_python_module_ctia_positive_event(module_tool_client):
    """Perform testing for event entity of custom threat intelligence python
    module

    ID: CCTRI-162-b3ecaf2b-7d15-43a5-80bb-879f4a2ce34b

    Steps:

        1. Send SEARCH request to server to get random event entity id
        2. Send GET request to server using that id
        3. Validate returned data contains information about event

    Expectedresults: Requests sent successfully and got valid response
        from server

    Importance: Critical
    """
    event = module_tool_client.private_intel.event
    entities_list = event.search(params={'query': '*'})
    assert len(entities_list) > 0
    entity = random.choice(entities_list)
    assert entity['type'] == 'event'
    get_tool_response = event.get(entity['id'].rpartition('/')[-1])
    assert get_tool_response['type'] == 'event'
    assert get_tool_response['timestamp']


def test_python_module_ctia_positive_feed(module_headers, module_tool_client):
    """Perform testing for feed entity of custom threat intelligence python
    module

    ID: CCTRI-906-e0114e1d-bfad-4776-810c-66ca351027d7

    Steps:

        1. Send POST request to create one judgement entity with one observable
        2. Send POST request to create one indicator entity to be used for
            feed functionality
        3. Send POST request to create new relationship between judgement and
            indicator
        4. Send POST request to create new feed entity using custom python
            module
        5. Send GET request using custom python module to read just created
            entity back.
        5. Send same GET request, but using direct access to the server
        6. Compare results
        7. Update relationship entity using custom python module
        8. Repeat GET request using python module and validate that entity was
            updated
        9. Send GET request using custom python module to read view endpoint
        10. Send GET request using custom python module to read view txt
            endpoint
        11. Delete entity from the system

    Expectedresults: Feed entity can be created, fetched, updated and
        deleted using custom python module. Data stored in the entity is
        the same no matter you access it directly or using our tool

    Importance: Critical
    """
    # Prepare data for judgement
    observable = {'type': 'ip', 'value': gen_ip()}
    judgement = module_tool_client.private_intel.judgement
    payload = {
        'confidence': 'High',
        'disposition': 2,
        'disposition_name': 'Malicious',
        'observable': observable,
        'priority': 99,
        'schema_version': SERVER_VERSION,
        'severity': 'Medium',
        'source': 'source',
        'type': 'judgement',
    }
    # Create new entity using provided payload
    judgement_post_response = judgement.post(
        payload=payload, params={'wait_for': 'true'})
    # Prepare data for indicator
    indicator = module_tool_client.private_intel.indicator
    payload = {
        "description": "The IP Blacklist",
        "producer": "ATQC team",
        "source": "ATQC generated test data",
        "source_uri": "https://atqc.com/bad",
        "title": "ATQC Bad IP",
        "type": "indicator",
        "valid_time": {
            "end_time": "2525-01-01T00:00:00.000Z",
            "start_time": "2019-03-01T22:26:29.229Z"
        }
    }
    # Create new indicator using provided payload
    indicator_post_response = indicator.post(
        payload=payload, params={'wait_for': 'true'})
    # Use created entities for relationship
    relationship = module_tool_client.private_intel.relationship
    payload = {
        'description': 'Demo relation',
        'schema_version': SERVER_VERSION,
        'type': 'relationship',
        'source_ref': judgement_post_response['id'],
        'target_ref': indicator_post_response['id'],
        'relationship_type': 'indicates',
    }
    # Create new entity using provided payload
    relationship.post(payload=payload, params={'wait_for': 'true'})
    # Prepare data for feed
    feed = module_tool_client.private_intel.feed
    payload = {
        "schema_version": SERVER_VERSION,
        "revision": 0,
        "indicator_id": indicator_post_response['id'],
        "type": "feed",
        "output": "observables",
        "feed_type": "indicator",
    }
    # Create new entity using provided payload
    post_tool_response = feed.post(
        payload=payload, params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'schema_version',
            'revision',
            'output',
            'type',
            'indicator_id',
            'feed_type'
        ]
    }
    assert values == payload
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_tool_response = feed.get(entity_id)
    get_direct_response = ctia_get_data(
        target_url=FEED,
        entity_id=entity_id,
        **{'headers': module_headers}
    ).json()
    assert get_tool_response == get_direct_response
    # Update entity values
    put_tool_response = delayed_return(
        feed.put(
            id_=entity_id,
            payload={
                "revision": 1,
                "indicator_id": indicator_post_response['id'],
                "type": "feed",
                "output": "observables",
                "feed_type": "indicator",
            }
        )
    )
    assert put_tool_response['revision'] == 1
    get_tool_response = feed.get(entity_id)
    assert get_tool_response['revision'] == 1
    # Get information from feed view endpoint
    assert feed.view(entity_id, get_tool_response['secret']) == (
        {'observables': [observable]}
    )
    # Get information from feed view text endpoint
    assert feed.view.txt(
        entity_id, get_tool_response['secret']) == observable['value']
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(feed.delete(entity_id))
    with pytest.raises(HTTPError):
        feed.get(entity_id)


def test_python_module_ctia_positive_feedback(
        module_headers, module_tool_client):
    """Perform testing for feedback entity of custom threat intelligence python
    module

    ID: CCTRI-162-9e48dd45-c211-4d0e-b909-c28badb790ac

    Steps:

        1. Send POST request to create new campaign entity using custom python
            module to provide source data for feedback entity
        2. Send GET request using custom python module to read just created
            feedback entity back.
        3. Send same GET request, but using direct access to the server
        4. Compare results
        5. Delete entity from the system

    Expectedresults: Feedback entity can be created, fetched and deleted using
        custom python module. Data stored in the entity is the same no matter
        you access it directly or using our tool

    Importance: Critical
    """
    campaign = module_tool_client.private_intel.campaign
    payload = {
        'campaign_type': 'Critical',
        'confidence': 'Medium',
        'type': 'campaign',
        'schema_version': SERVER_VERSION
    }
    # Create new campaign entity to be used for feedback
    post_tool_response = campaign.post(payload=payload,
                                       params={'wait_for': 'true'})
    campaign_entity_id = post_tool_response['id'].rpartition('/')[-1]
    feedback = module_tool_client.private_intel.feedback
    payload = {
        'schema_version': SERVER_VERSION,
        'type': 'feedback',
        'feedback': 1,
        'reason': 'improvement',
        'entity_id': campaign_entity_id
    }
    # Create new feedback entity using provided payload with already formed
    # campaign entity
    post_tool_response = feedback.post(payload=payload,
                                       params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'feedback',
            'reason',
            'entity_id',
            'type',
            'schema_version'
        ]
    }
    assert values == payload
    feedback_entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_tool_response = feedback.get(feedback_entity_id)
    get_direct_response = ctia_get_data(
        target_url=FEEDBACK,
        entity_id=feedback_entity_id,
        **{'headers': module_headers}
    ).json()
    assert get_tool_response == get_direct_response
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(feedback.delete(feedback_entity_id))
    with pytest.raises(HTTPError):
        feedback.get(feedback_entity_id)


def test_python_module_ctia_positive_graphql(module_tool_client):
    """Perform testing for graphql entity of custom threat intelligence python
    module

    ID: CCTRI-162-eed3e3ae-39b3-4c38-ae60-c22c412b2d15

    Steps:

        1. Send POST request to server to execute GraphQL query using custom
            python module

    Expectedresults: POST request sent successfully and got valid response
        from server

    Importance: Critical
    """
    query = (
        'query Sightings($query: String, $first: Int) {sightings(query:'
        ' $query, first: $first, orderBy: [{field: OBSERVED_TIME_START_TIME,'
        ' direction: desc}]) {nodes {observables {value type} confidence'
        ' severity description resolution source source_uri observed_time'
        ' {start_time end_time} relations {relation source {value type}'
        ' related {value type}}}}}'
    )
    payload = {
        'query': query,
        'variables': {'query': 'tags:"ransomware"', 'first': 100}
    }
    # Create new entity using provided payload
    post_tool_response = module_tool_client.private_intel.graphql.post(
        payload=payload, params={'wait_for': 'true'})
    assert post_tool_response


def test_python_module_ctia_positive_identity_assertion(
        module_headers, module_tool_client):
    """Perform testing for identity assertion entity of custom threat
    intelligence python module

    ID: CCTRI-906-3fed238c-cd4c-45b5-a4c9-06c9ac29eb9a

    Steps:

        1. Send POST request to create new identity assertion entity using
            custom python module
        2. Send GET request using custom python module to read just created
            entity back.
        3. Send same GET request, but using direct access to the server
        4. Compare results
        5. Update identity assertion entity using custom python module
        6. Repeat GET request using python module and validate that entity was
            updated
        7. Delete entity from the system

    Expectedresults: Identity assertion entity can be created, fetched,
        updated and deleted using custom python module. Data stored in the
        entity is the same no matter you access it directly or using our tool

    Importance: Critical
    """
    identity_assertion = module_tool_client.private_intel.identity_assertion
    payload = {
        'identity': {
            'observables': [
                {
                    'type': 'ip',
                    'value': '10.0.0.1'
                },
            ]
        },
        'schema_version': SERVER_VERSION,
        'type': 'identity-assertion',
        'source': 'ATQC data',
        'assertions': [
            {
                'name': 'severity',
                'value': 'Medium'
            }
        ],
    }
    # Create new entity using provided payload
    post_tool_response = identity_assertion.post(
        payload=payload, params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'identity',
            'assertions',
            'schema_version',
            'source',
            'type'
        ]
    }
    assert values == payload
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_tool_response = identity_assertion.get(entity_id)
    get_direct_response = ctia_get_data(
        target_url=IDENTITY_ASSERTION,
        entity_id=entity_id,
        **{'headers': module_headers}
    ).json()
    assert get_tool_response == get_direct_response
    # Update entity values
    put_tool_response = delayed_return(
        identity_assertion.put(
            id_=entity_id,
            payload={
                'identity': {
                    'observables': [
                        {
                            'type': 'ip',
                            'value': '10.0.0.1'
                        },
                    ]
                },
                'assertions': [
                    {
                        'name': 'severity',
                        'value': 'Low'
                    }
                ],
            }
        )
    )
    assert put_tool_response['assertions'][0]['value'] == 'Low'
    get_tool_response = identity_assertion.get(entity_id)
    assert get_tool_response['assertions'][0]['value'] == 'Low'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(identity_assertion.delete(entity_id))
    with pytest.raises(HTTPError):
        identity_assertion.get(entity_id)


def test_python_module_ctia_positive_incident(
        module_headers, module_tool_client):
    """Perform testing for incident entity of custom threat intelligence python
    module

    ID: CCTRI-163-e633504e-0b62-4c28-a86f-a43b5bcd53b0

    Steps:

        1. Send POST request to create new incident entity using custom python
            module
        2. Send GET request using custom python module to read just created
            entity back.
        3. Send same GET request, but using direct access to the server
        4. Compare results
        5. Update incident entity using custom python module
        6. Repeat GET request using python module and validate that entity was
            updated
        7. Send PATCH request to update entity partially
        8. Repeat GET request to validate that entity was updated
        9. Update incident status using special endpoint for that purpose
        10. Repeat GET request to validate that status was updated
        11. Delete entity from the system

    Expectedresults: Incident entity can be created, fetched, updated and
        deleted using custom python module. Data stored in the entity is
        the same no matter you access it directly or using our tool

    Importance: Critical
    """
    incident = module_tool_client.private_intel.incident
    payload = {
        'confidence': 'High',
        'incident_time': {
            'opened': "2016-02-11T00:40:48.212Z"
        },
        'status': 'Open',
        'type': 'incident',
        'schema_version': SERVER_VERSION
    }
    # Create new entity using provided payload
    post_tool_response = incident.post(payload=payload,
                                       params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'confidence',
            'incident_time',
            'status',
            'type',
            'schema_version'
        ]
    }
    assert values == payload
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_tool_response = incident.get(entity_id)
    get_direct_response = ctia_get_data(
        target_url=INCIDENT,
        entity_id=entity_id,
        **{'headers': module_headers}
    ).json()
    assert get_tool_response == get_direct_response
    # Update entity values
    put_tool_response = delayed_return(
        incident.put(
            id_=entity_id,
            payload={
                'confidence': 'Medium',
                'incident_time': {
                    'opened': "2016-02-11T00:40:48.212Z"
                },
                'status': 'Open',
            }
        )
    )
    assert put_tool_response['confidence'] == 'Medium'
    get_tool_response = incident.get(entity_id)
    assert get_tool_response['confidence'] == 'Medium'
    # Validate PATCH request
    patch_tool_response = delayed_return(
        incident.patch(id_=entity_id, payload={'confidence': 'Low'}))
    assert patch_tool_response['confidence'] == 'Low'
    get_tool_response = incident.get(entity_id)
    assert get_tool_response['confidence'] == 'Low'
    # Validate status endpoint
    assert get_tool_response['status'] == 'Open'
    delayed_return(incident.status(entity_id, {'status': 'New'}))
    get_tool_response = incident.get(entity_id)
    assert get_tool_response['status'] == 'New'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(incident.delete(entity_id))
    with pytest.raises(HTTPError):
        incident.get(entity_id)


def test_python_module_ctia_positive_indicator(
        module_headers, module_tool_client):
    """Perform testing for indicator entity of custom threat intelligence python
    module

    ID: CCTRI-163-f73c4512-9faa-462f-929f-c7ae3f79f887

    Steps:

        1. Send POST request to create new indicator entity using custom python
            module
        2. Send GET request using custom python module to read just created
            entity back.
        3. Send same GET request, but using direct access to the server
        4. Compare results
        5. Update indicator entity using custom python module
        6. Repeat GET request using python module and validate that entity was
            updated
        7. Delete entity from the system

    Expectedresults: Indicator entity can be created, fetched, updated and
        deleted using custom python module. Data stored in the entity is
        the same no matter you access it directly or using our tool

    Importance: Critical
    """
    indicator = module_tool_client.private_intel.indicator
    payload = {
        'producer': 'producer',
        'schema_version': SERVER_VERSION,
        'type': 'indicator',
        'revision': 0
    }
    # Create new entity using provided payload
    post_tool_response = indicator.post(payload=payload,
                                        params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'producer',
            'revision',
            'type',
            'schema_version'
        ]
    }
    assert values == payload
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_tool_response = indicator.get(entity_id)
    get_direct_response = ctia_get_data(
        target_url=INDICATOR,
        entity_id=entity_id,
        **{'headers': module_headers}
    ).json()
    assert get_tool_response == get_direct_response
    # Update entity values
    put_tool_response = delayed_return(
        indicator.put(
            id_=entity_id,
            payload={
                'revision': 1,
                'producer': 'producer',
            }
        )
    )
    assert put_tool_response['revision'] == 1
    get_tool_response = indicator.get(entity_id)
    assert get_tool_response['revision'] == 1
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(indicator.delete(entity_id))
    with pytest.raises(HTTPError):
        indicator.get(entity_id)


def test_python_module_ctia_positive_investigation(
        module_headers, module_tool_client):
    """Perform testing for investigation entity of custom threat intelligence
    python module

    ID: CCTRI-167-90f58543-649d-442b-84ec-9a8f4de83d21

    Steps:

        1. Send POST request to create new investigation entity using custom
            python module
        2. Send GET request using custom python module to read just created
            entity back.
        3. Send same GET request, but using direct access to the server
        4. Compare results
        5. Update investigation entity using custom python module
        6. Repeat GET request using python module and validate that entity was
            updated
        7. Delete entity from the system

    Expectedresults: Investigation entity can be created, fetched, updated and
        deleted using custom python module. Data stored in the entity is
        the same no matter you access it directly or using our tool

    Importance: Critical
    """
    investigation = module_tool_client.private_intel.investigation
    payload = {
        'title': 'Demo investigation',
        'description': 'Request investigation for yesterday malware',
        'type': 'investigation',
        'source': 'a source',
        'schema_version': SERVER_VERSION
    }
    # Create new entity using provided payload
    post_tool_response = investigation.post(payload=payload,
                                            params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'title',
            'description',
            'source',
            'type',
            'schema_version'
        ]
    }
    assert values == payload
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_tool_response = investigation.get(entity_id)
    get_direct_response = ctia_get_data(
        target_url=INVESTIGATION,
        entity_id=entity_id,
        **{'headers': module_headers}
    ).json()
    assert get_tool_response == get_direct_response
    # Update entity values
    put_tool_response = delayed_return(
        investigation.put(
            id_=entity_id,
            payload={'title': 'New demo investigation', 'source': 'a source'}
        )
    )
    assert put_tool_response['title'] == 'New demo investigation'
    get_tool_response = investigation.get(entity_id)
    assert get_tool_response['title'] == 'New demo investigation'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(investigation.delete(entity_id))
    with pytest.raises(HTTPError):
        investigation.get(entity_id)


def test_python_module_ctia_positive_judgement(
        module_headers, module_tool_client):
    """Perform testing for judgement entity of custom threat intelligence
    python module

    ID: CCTRI-163-75d6960a-6bf3-40cd-965c-c53a81cb0ffd

    Steps:

        1. Send POST request to create new judgement entity using custom python
            module
        2. Send GET request using custom python module to read just created
            entity back.
        3. Send same GET request, but using direct access to the server
        4. Compare results
        5. Make an attempt to update judgement entity using custom python
            module
        6. Check that error is returned
        7. Delete entity from the system

    Expectedresults: Judgement entity can be created, fetched and deleted
        using custom python module. Data stored in the entity is the same
        no matter you access it directly or using our tool

    Importance: Critical
    """
    judgement = module_tool_client.private_intel.judgement
    payload = {
        'confidence': 'High',
        'disposition': 1,
        'disposition_name': 'Clean',
        'observable': {
            'type': 'ip',
            'value': '10.0.0.1'
        },
        'priority': 99,
        'schema_version': SERVER_VERSION,
        'severity': 'Medium',
        'source': 'source',
        'type': 'judgement',
    }
    # Create new entity using provided payload
    post_tool_response = judgement.post(payload=payload,
                                        params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'confidence',
            'disposition',
            'disposition_name',
            'observable',
            'priority',
            'schema_version',
            'observable',
            'severity',
            'source',
            'type',
        ]
    }
    assert values == payload
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_tool_response = judgement.get(entity_id)
    get_direct_response = ctia_get_data(
        target_url=JUDGEMENT,
        entity_id=entity_id,
        **{'headers': module_headers}
    ).json()
    assert get_tool_response == get_direct_response
    # Make an attempt to update Judgement using endpoint which is not
    # implemented in application
    with pytest.raises(HTTPError) as context:
        judgement.put(
            id_=entity_id,
            payload={
                'confidence': 'High',
                'priority': 43,
                'severity': 'High',
                'observable': {
                    'type': 'ip',
                    'value': '10.0.0.1'
                },
                'source': 'source',
            }
        )
    assert '"error": "missing_capability"' in str(context.value)
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(judgement.delete(entity_id))
    with pytest.raises(HTTPError):
        judgement.get(entity_id)


def test_python_module_ctia_positive_malware(
        module_headers, module_tool_client):
    """Perform testing for malware entity of custom threat intelligence python
    module

    ID: CCTRI-164-056ef37c-171d-4b1d-ae3d-4601aaa465bb

    Steps:

        1. Send POST request to create new malware entity using custom python
            module
        2. Send GET request using custom python module to read just created
            entity back.
        3. Send same GET request, but using direct access to the server
        4. Compare results
        5. Update malware entity using custom python module
        6. Repeat GET request using python module and validate that entity was
            updated
        7. Delete entity from the system

    Expectedresults: Malware entity can be created, fetched, updated and
        deleted using custom python module. Data stored in the entity is
        the same no matter you access it directly or using our tool

    Importance: Critical
    """
    malware = module_tool_client.private_intel.malware
    payload = {
        'type': 'malware',
        'schema_version': SERVER_VERSION,
        'name': 'TinyZBot',
        'labels': ['malware']
    }
    # Create new entity using provided payload
    post_tool_response = malware.post(payload=payload,
                                      params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'name',
            'labels',
            'type',
            'schema_version'
        ]
    }
    assert values == payload
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_tool_response = malware.get(entity_id)
    get_direct_response = ctia_get_data(
        target_url=MALWARE,
        entity_id=entity_id,
        **{'headers': module_headers}
    ).json()
    assert get_tool_response == get_direct_response
    # Update entity values
    put_tool_response = delayed_return(
        malware.put(
            id_=entity_id,
            payload={'name': 'XBot', 'labels': ['malware']}
        )
    )
    assert put_tool_response['name'] == 'XBot'
    get_tool_response = malware.get(entity_id)
    assert get_tool_response['name'] == 'XBot'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(malware.delete(entity_id))
    with pytest.raises(HTTPError):
        malware.get(entity_id)


def test_python_module_ctia_positive_relationship(
        module_headers, module_tool_client):
    """Perform testing for relationship entity of custom threat intelligence
    python module

    ID: CCTRI-164-f3c6e3c2-b437-4db9-a630-3c6072517ff2

    Steps:

        1. Send POST request to create one campaign entity to be used for
            relationship functionality
        2. Send POST request to create one indicator entity to be used for
            relationship functionality
        3. Send POST request to create new relationship entity using custom
            python module
        4. Send GET request using custom python module to read just created
            entity back.
        5. Send same GET request, but using direct access to the server
        6. Compare results
        7. Update relationship entity using custom python module
        8. Repeat GET request using python module and validate that entity was
            updated
        9. Delete entity from the system

    Expectedresults: Relationship entity can be created, fetched, updated and
        deleted using custom python module. Data stored in the entity is the
        same no matter you access it directly or using our tool

    Importance: Critical
    """
    # Prepare data for campaign
    campaign = module_tool_client.private_intel.campaign
    payload = {
        'campaign_type': 'Low',
        'confidence': 'Medium',
        'type': 'campaign',
        'schema_version': SERVER_VERSION
    }
    # Create new campaign using provided payload
    campaign_post_response = campaign.post(payload=payload,
                                           params={'wait_for': 'true'})
    # Prepare data for indicator
    indicator = module_tool_client.private_intel.indicator
    payload = {
        'producer': 'producer',
        'schema_version': SERVER_VERSION,
        'type': 'indicator',
        'revision': 0
    }
    # Create new indicator using provided payload
    indicator_post_response = indicator.post(payload=payload,
                                             params={'wait_for': 'true'})
    # Use created entities for relationship
    relationship = module_tool_client.private_intel.relationship
    payload = {
        'description': 'Demo relation',
        'schema_version': SERVER_VERSION,
        'type': 'relationship',
        'source_ref': campaign_post_response['id'],
        'target_ref': indicator_post_response['id'],
        'relationship_type': 'indicates',
    }
    # Create new entity using provided payload
    post_tool_response = relationship.post(payload=payload,
                                           params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'description',
            'source_ref',
            'target_ref',
            'relationship_type',
            'type',
            'schema_version'
        ]
    }
    assert values == payload
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_tool_response = relationship.get(entity_id)
    get_direct_response = ctia_get_data(
        target_url=RELATIONSHIP,
        entity_id=entity_id,
        **{'headers': module_headers}
    ).json()
    assert get_tool_response == get_direct_response
    # Update entity values
    put_tool_response = delayed_return(
        relationship.put(
            id_=entity_id,
            payload={
                'description': 'New demo relation',
                'source_ref': campaign_post_response['id'],
                'target_ref': indicator_post_response['id'],
                'relationship_type': 'indicates',
            }
        )
    )
    assert put_tool_response['description'] == 'New demo relation'
    get_tool_response = relationship.get(entity_id)
    assert get_tool_response['description'] == 'New demo relation'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(relationship.delete(entity_id))
    with pytest.raises(HTTPError):
        relationship.get(entity_id)


def test_python_module_ctia_positive_sighting(
        module_headers, module_tool_client):
    """Perform testing for sighting entity of custom threat intelligence python
    module

    ID: CCTRI-165-6fe55f8c-a148-4d7c-8a27-fbbec825819f

    Steps:

        1. Send POST request to create new sighting entity using custom python
            module
        2. Send GET request using custom python module to read just created
            entity back.
        3. Send same GET request, but using direct access to the server
        4. Compare results
        5. Update sighting entity using custom python module
        6. Repeat GET request using python module and validate that entity was
            updated
        7. Delete entity from the system

    Expectedresults: Sighting entity can be created, fetched, updated and
        deleted using custom python module. Data stored in the entity is
        the same no matter you access it directly or using our tool

    Importance: Critical
    """
    sighting = module_tool_client.private_intel.sighting
    payload = {
        'count': 1,
        'observed_time': {
            'start_time': '2019-09-25T00:40:48.212Z',
            'end_time': '2019-09-25T00:40:48.212Z'
        },
        'confidence': 'High',
        'type': 'sighting',
        'schema_version': SERVER_VERSION
    }
    # Create new entity using provided payload
    post_tool_response = sighting.post(payload=payload,
                                       params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'count',
            'observed_time',
            'confidence',
            'type',
            'schema_version'
        ]
    }
    assert values == payload
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_tool_response = sighting.get(entity_id)
    get_direct_response = ctia_get_data(
        target_url=SIGHTING,
        entity_id=entity_id,
        **{'headers': module_headers}
    ).json()
    assert get_tool_response == get_direct_response
    # Update entity values
    put_tool_response = delayed_return(
        sighting.put(
            id_=entity_id,
            payload={
                'confidence': 'Low',
                'observed_time': {
                    'start_time': '2019-09-25T00:40:48.212Z',
                    'end_time': '2019-09-25T00:40:48.212Z'
                },
            }
        )
    )
    assert put_tool_response['confidence'] == 'Low'
    get_tool_response = sighting.get(entity_id)
    assert get_tool_response['confidence'] == 'Low'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(sighting.delete(entity_id))
    with pytest.raises(HTTPError):
        sighting.get(entity_id)


def test_python_module_ctia_positive_status(module_tool_client):
    """Perform testing for status endpoint using custom threat intelligence
    python module

    ID: CCTRI-167-29cdff9c-0d48-4f73-acdb-b77795e3ad0f

    Steps:

        1. Send GET request to server using custom python module
        2. Validate returned data

    Expectedresults: Response contains information about server health status

    Importance: Critical
    """
    status = module_tool_client.private_intel.status
    server_status = status.get()
    assert server_status['status'] == 'ok'


def test_python_module_ctia_positive_tool(module_headers, module_tool_client):
    """Perform testing for tool entity of custom threat intelligence python
    module

    ID: CCTRI-166-ebdfccab-a751-43fe-974f-037da0b10153

    Steps:

        1. Send POST request to create new tool entity using custom python
            module
        2. Send GET request using custom python module to read just created
            entity back.
        3. Send same GET request, but using direct access to the server
        4. Compare results
        5. Update tool entity using custom python module
        6. Repeat GET request using python module and validate that entity was
            updated
        7. Delete entity from the system

    Expectedresults: Tool entity can be created, fetched, updated and
        deleted using custom python module. Data stored in the entity is
        the same no matter you access it directly or using our tool

    Importance: Critical
    """
    tool = module_tool_client.private_intel.tool
    payload = {
        'name': 'cmd',
        'labels': ['tool'],
        'type': 'tool',
        'schema_version': SERVER_VERSION
    }
    # Create new entity using provided payload
    post_tool_response = tool.post(payload=payload,
                                   params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'name',
            'labels',
            'type',
            'schema_version'
        ]
    }
    assert values == payload
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_tool_response = tool.get(entity_id)
    get_direct_response = ctia_get_data(
        target_url=TOOL,
        entity_id=entity_id,
        **{'headers': module_headers}
    ).json()
    assert get_tool_response == get_direct_response
    # Update entity values
    put_tool_response = delayed_return(
        tool.put(
            id_=entity_id,
            payload={'name': 'gedit', 'labels': ['tool']}
        )
    )
    assert put_tool_response['name'] == 'gedit'
    get_tool_response = tool.get(entity_id)
    assert get_tool_response['name'] == 'gedit'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(tool.delete(entity_id))
    with pytest.raises(HTTPError):
        tool.get(entity_id)
    # Validate CCTRI-1036 defect
    with pytest.raises(HTTPError):
        tool.delete(entity_id)


def test_python_module_ctia_positive_verdict(
        module_headers, module_tool_client):
    """Perform testing for verdict entity of custom threat intelligence python
    module

    ID: CCTRI-166-ebdfccab-a751-43fe-974f-037da0b10153

    Steps:

        1. Send POST request to create new judgement entity using custom python
            module to provide source data for verdict entity
        2. Send GET request using custom python module to read verdict entity
            based on just created one.
        3. Send same GET request, but using direct access to the server
        4. Compare results

    Expectedresults: Verdict entity can be fetched using custom python module.
        Data stored in the entity is the same no matter you access it directly
        or using our tool

    Importance: Critical
    """
    judgement = module_tool_client.private_intel.judgement
    payload = {
        'confidence': 'High',
        'disposition': 1,
        'disposition_name': 'Clean',
        'observable': {
            'type': 'ip',
            'value': '10.0.0.2'
        },
        'priority': 15,
        'schema_version': SERVER_VERSION,
        'severity': 'Medium',
        'source': 'source',
        'type': 'judgement',
    }
    # Create new judgement entity to be used for verdict
    judgement.post(payload=payload, params={'wait_for': 'true'})
    verdict = module_tool_client.private_intel.verdict
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_tool_response = verdict.get('ip', '10.0.0.2')
    assert get_tool_response['type'] == 'verdict'
    get_direct_response = ctia_get_data(
        target_url=VERDICT.format('ip', '10.0.0.2'),
        **{'headers': module_headers}
    ).json()
    assert get_tool_response == get_direct_response


def test_python_module_ctia_positive_version(module_tool_client):
    """Perform testing for version endpoint using custom threat intelligence
    python module

    ID: CCTRI-167-0d9be838-5aad-4f81-99bd-ead69a9c2d08

    Steps:

        1. Send GET request to server using custom python module
        2. Validate returned data

    Expectedresults: Response contains information about server version

    Importance: Critical
    """
    version = module_tool_client.private_intel.version
    server_version = version.get()
    assert server_version['base'] == '/ctia'
    assert server_version['ctim-version'] == SERVER_VERSION


def test_python_module_ctia_positive_vulnerability(
        module_headers, module_tool_client):
    """Perform testing for vulnerability entity of custom threat intelligence
    python module

    ID: CCTRI-168-4a43be85-6d16-46db-b54f-6b05e9b68ab2

    Steps:

        1. Send POST request to create new vulnerability entity using custom
            python module
        2. Send GET request using custom python module to read just created
            entity back.
        3. Send same GET request, but using direct access to the server
        4. Compare results
        5. Update vulnerability entity using custom python module
        6. Repeat GET request using python module and validate that entity was
            updated
        7. Delete entity from the system

    Expectedresults: Vulnerability entity can be created, fetched, updated and
        deleted using custom python module. Data stored in the entity is
        the same no matter you access it directly or using our tool

    Importance: Critical
    """
    vulnerability = module_tool_client.private_intel.vulnerability
    payload = {
        'description': 'Browser vulnerability',
        'type': 'vulnerability',
        'schema_version': SERVER_VERSION,
    }
    # Create new entity using provided payload
    post_tool_response = vulnerability.post(payload=payload,
                                            params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'description',
            'type',
            'schema_version'
        ]
    }
    assert values == payload
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_tool_response = vulnerability.get(entity_id)
    get_direct_response = ctia_get_data(
        target_url=VULNERABILITY,
        entity_id=entity_id,
        **{'headers': module_headers}
    ).json()
    assert get_tool_response == get_direct_response
    # Update entity values
    put_tool_response = delayed_return(
        vulnerability.put(
            id_=entity_id,
            payload={'description': 'New browser vulnerability'}
        )
    )
    assert put_tool_response['description'] == 'New browser vulnerability'
    get_tool_response = vulnerability.get(entity_id)
    assert get_tool_response['description'] == 'New browser vulnerability'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(vulnerability.delete(entity_id))
    with pytest.raises(HTTPError):
        vulnerability.get(entity_id)


def test_python_module_ctia_positive_weakness(
        module_headers, module_tool_client):
    """Perform testing for weakness entity of custom threat intelligence python
    module

    ID: CCTRI-168-7de38006-e939-4a2a-b2d8-b752d3527182

    Steps:

        1. Send POST request to create new weakness entity using custom python
            module
        2. Send GET request using custom python module to read just created
            entity back.
        3. Send same GET request, but using direct access to the server
        4. Compare results
        5. Update weakness entity using custom python module
        6. Repeat GET request using python module and validate that entity was
            updated
        7. Delete entity from the system

    Expectedresults: Weakness entity can be created, fetched, updated and
        deleted using custom python module. Data stored in the entity is
        the same no matter you access it directly or using our tool

    Importance: Critical
    """
    weakness = module_tool_client.private_intel.weakness
    payload = {
        'description': (
            'The software receives input from an upstream component, but it'
            ' does not neutralize or incorrectly neutralizes code syntax'
            ' before using the input in a dynamic evaluation call'
            ' (e.g. \"eval\").'),
        'schema_version': SERVER_VERSION,
        'likelihood': 'Medium',
        'type': 'weakness'
    }
    # Create new entity using provided payload
    post_tool_response = weakness.post(payload=payload,
                                       params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'description',
            'likelihood',
            'type',
            'schema_version'
        ]
    }
    assert values == payload
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_tool_response = weakness.get(entity_id)
    get_direct_response = ctia_get_data(
        target_url=WEAKNESS,
        entity_id=entity_id,
        **{'headers': module_headers}
    ).json()
    assert get_tool_response == get_direct_response
    # Update entity values
    put_tool_response = delayed_return(
        weakness.put(
            id_=entity_id,
            payload={'likelihood': 'High', 'description': 'New description'}
        )
    )
    assert put_tool_response['likelihood'] == 'High'
    assert put_tool_response['description'] == 'New description'
    get_tool_response = weakness.get(entity_id)
    assert get_tool_response['likelihood'] == 'High'
    assert get_tool_response['description'] == 'New description'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(weakness.delete(entity_id))
    with pytest.raises(HTTPError):
        weakness.get(entity_id)
