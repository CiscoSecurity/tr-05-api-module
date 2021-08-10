import pytest
import random
import json
from requests import HTTPError
from ctrlibrary.core.datafactory import gen_ip
from ctrlibrary.core.utils import delayed_return
from ctrlibrary.ctia.base import ctia_get_data
from ctrlibrary.ctia.endpoints import (
    ACTOR,
    ASSET,
    ASSET_MAPPING,
    ASSET_PROPERTIES,
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
    TARGET_RECORD,
    TOOL,
    VERDICT,
    VULNERABILITY,
    WEAKNESS,
)

SERVER_VERSION = '1.1.3'


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
        'description': 'For Test',
        'confidence': 'High',
        'schema_version': SERVER_VERSION,
        'source': 'test source',
        'type': 'actor',
        'short_description': 'test',
        'title': 'for test'
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
            'type',
            'description',
            'short_description',
            'title'
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
            payload={'source': 'new source point',
                     'actor_type': 'Hacker',
                     'description': 'for Test',
                     'confidence': 'High',
                     'schema_version': SERVER_VERSION,
                     'type': 'actor',
                     'short_description': 'test',
                     'title': 'for test'
                     }
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


def test_python_module_ctia_positive_actor_search(module_headers,
                                                  module_tool_client):
    """Perform testing for actor/search entity of custom threat
    intelligence python module

    ID: CCTRI-2848 - 9ba48f7c-19b5-45d9-b5f7-7966795c4abe

    Steps:

        1. Send POST request to create new actor entity using custom python
                module
        2. Send GET request using custom python module to read just created
                entity back.
        3. Count entities after entity created
        4. Delete entity from the system
        5. Repeat GET request using python module and validate that entity was
            deleted
        6. Count entities after entity deleted
        7. Compare the amount of entities after creating and deleting entities

    Expectedresults: Actor entity can be created, fetched, counted and
        deleted using custom python module. Data stored in the entity is
        the same no matter you access it directly or using our tool

    Importance: Critical
    """
    actor = module_tool_client.private_intel.actor
    payload = {
        'source': 'new source point',
        'actor_type': 'Hacker',
        'description': 'for Test',
        'confidence': 'High',
        'schema_version': SERVER_VERSION,
        'type': 'actor',
        'short_description': 'test',
        'title': 'for test'
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
            'type',
            'description',
            'short_description',
            'title'
        ]
    }
    assert values == payload
    # Create variable for using it in params for endpoints
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_actor_search = actor.search.get(params={'id': entity_id})
    assert get_actor_search[0]['type'] == 'actor'
    assert get_actor_search[0]['description'] == 'for Test'
    # Count entities after entity created
    get_actor_search_count = actor.search.count()
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(actor.search.delete(params={'id': entity_id,
                                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert actor.search.get(params={'id': entity_id}) == []
    # Count entities after entity deleted
    get_actor_search_count2 = actor.search.count()
    # Compare results of get_actor_search_count and get_actor_search_count2
    assert get_actor_search_count != get_actor_search_count2


def test_python_module_ctia_positive_actor_metric(module_headers,
                                                  module_tool_client):
    """Perform testing for actor/metric endpoints of custom threat
    intelligence python module

    ID: CCTRI-2848 -52c89f1b-9728-41d6-8a1f-07dd0ec8b976

    Steps:

        1. Send POST request to create new actor entity using custom python
                module
        2. Send GET request using custom python module to read just created
                 entity back.
        3. Send GET request to get type of metric/histogram endpoint
        4. Send GET request to get type of metric/topn endpoint
        5. Send GET request to get type of metric/cardinality endpoint
        6. Delete created entity
        7. Repeat GET request using python module and validate that entity was
            deleted

     Expectedresults: Actor entity can be created, fetched, researched by
         metric's endpoints and deleted using custom python module.
         Data stored in the entity is the same no matter you access it
         directly or using our tool.

    Importance: Critical
    """
    actor = module_tool_client.private_intel.actor
    payload = {
        'source': 'Test source',
        'actor_type': 'Hacker',
        'description': 'for Test',
        'confidence': 'High',
        'schema_version': SERVER_VERSION,
        'type': 'actor',
        'short_description': 'test',
        'title': 'for test'
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
            'type',
            'description',
            'short_description',
            'title'
        ]
    }
    assert values == payload
    # Create variable for using it in params for endpoints
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_created_actor = actor.get(entity_id)
    assert get_created_actor['type'] == 'actor'
    assert get_created_actor['description'] == 'for Test'
    assert get_created_actor['source'] == 'Test source'
    # Send GET request to get type of metric/histogram endpoint
    data_from = get_created_actor['timestamp']
    metric_histogram = actor.metric.histogram(params={'granularity': 'week',
                                                      'from': data_from,
                                                'aggregate-on': 'timestamp'})
    assert metric_histogram['type'] == 'histogram'
    # Send GET request to get type of metric/topn endpoint
    metric_topn = actor.metric.topn(params={'from': data_from,
                                                 'aggregate-on': 'source'})
    assert metric_topn['type'] == 'topn'
    # Send GET request to get type of metric/cardinality endpoint
    metric_cardinality = actor.metric.cardinality(params={'from': data_from,
                                            'aggregate-on': 'source'})
    assert metric_cardinality['type'] == 'cardinality'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(actor.search.delete(params={'id': entity_id,
                                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert actor.search.get(params={'id': entity_id}) == []


def test_python_module_ctia_positive_asset(module_headers, module_tool_client):
    """Perform testing for asset entity of custom threat intelligence python
    module

    ID: CCTRI-2848-85594b4a-d53f-4285-9aa8-c13e21858e4b

    Steps:

        1. Send POST request to create new asset entity using custom python
            module
        2. Send GET request using custom python module to read just created
            entity back.
        3. Send same GET request, but using direct access to the server
        4. Compare results
        5. Validate that GET request of external_id returns number of
        external_id
        6. Update asset entity using custom python module
        7. Repeat GET request using python module and validate that entity was
            updated
        8. Delete entity from the system

    Expectedresults: Asset entity can be created, fetched, updated and
        deleted using custom python module. Data stored in the entity is
        the same no matter you access it directly or using our tool

    Importance: Critical
    """
    asset = module_tool_client.private_intel.asset
    payload = {
        'asset_type': 'data',
        'description': 'For Test',
        'valid_time': {
            "start_time": "2021-07-27T07:55:38.193Z",
            "end_time": "2021-07-27T07:55:38.193Z"},
        'schema_version': SERVER_VERSION,
        'source': 'test source',
        'type': 'asset',
        'short_description': 'test',
        'title': 'for test',
        'external_ids': ['3']
    }
    # Create new entity using provided payload
    post_tool_response = asset.post(payload=payload,
                                    params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'asset_type',
            'valid_time',
            'schema_version',
            'source',
            'type',
            'description',
            'short_description',
            'title',
            'external_ids'
        ]
    }
    assert values == payload
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_tool_response = asset.get(entity_id)
    get_direct_response = ctia_get_data(
        target_url=ASSET,
        entity_id=entity_id,
        **{'headers': module_headers}
    ).json()
    assert get_tool_response == get_direct_response
    # Validate that GET request of external_id returns number of external_id
    external_id_result = asset.external_id(3)
    assert external_id_result[0]['external_ids'] == ['3']
    # Update entity values
    put_tool_response = delayed_return(
        asset.put(
            id_=entity_id,
            payload={'source': 'new source point',
                     'asset_type': 'device',
                     'description': 'for Test',
                     'valid_time': {
                      "start_time": "2021-07-27T07:55:38.193Z",
                      "end_time": "2021-07-27T07:55:38.193Z"},
                     'schema_version': SERVER_VERSION,
                     'type': 'asset',
                     'short_description': 'test',
                     'title': 'for test'
                     }
        )
    )
    assert put_tool_response['asset_type'] == 'device'
    get_tool_response = asset.get(entity_id)
    assert get_tool_response['source'] == 'new source point'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(asset.delete(entity_id))
    with pytest.raises(HTTPError):
        asset.get(entity_id)


def test_python_module_ctia_positive_asset_search(module_headers,
                                                  module_tool_client):
    """Perform testing for asset/search entity of custom threat
    intelligence python module

    ID: CCTRI-2848 - 593c7ea1-82f6-4484-beec-9aeecb20b4f3

    Steps:

        1. Send POST request to create new asset entity using custom python
                module
        2. Send GET request using custom python module to read just created
                entity back.
        3. Count entities after entity created
        4. Delete entity from the system
        5. Repeat GET request using python module and validate that entity was
            deleted
        6. Count entities after entity deleted
        7. Compare the amount of entities after creating and deleting entities

    Expectedresults: Asset entity can be created, fetched, counted and
        deleted using custom python module. Data stored in the entity is
        the same no matter you access it directly or using our tool

    Importance: Critical
    """
    asset = module_tool_client.private_intel.asset
    payload = {
        'asset_type': 'data',
        'description': 'For Test',
        'valid_time': {
            "start_time": "2021-07-27T07:55:38.193Z",
            "end_time": "2021-07-27T07:55:38.193Z"},
        'schema_version': SERVER_VERSION,
        'source': 'test source',
        'type': 'asset',
        'short_description': 'test',
        'title': 'for test'
    }
    # Create new entity using provided payload
    post_tool_response = asset.post(payload=payload,
                                    params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'asset_type',
            'valid_time',
            'schema_version',
            'source',
            'type',
            'description',
            'short_description',
            'title'
        ]
    }
    assert values == payload
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_asset_search = asset.search.get(params={'id': entity_id})
    assert get_asset_search[0]['type'] == 'asset'
    assert get_asset_search[0]['description'] == 'For Test'
    # Count entities after entity created
    get_asset_search_count = asset.search.count()
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(asset.search.delete(params={'id': entity_id,
                                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert asset.search.get(params={'id': entity_id}) == []
    # Count entities after entity deleted
    get_asset_search_count2 = asset.search.count()
    # Compare results of get_asset_search_count and get_asset_search_count2
    assert get_asset_search_count != get_asset_search_count2


def test_python_module_ctia_positive_asset_metric(module_headers,
                                                  module_tool_client):
    """Perform testing for asset/metric endpoints of custom threat
    intelligence python module

    ID: CCTRI-2848 -a1f492e4-5b8f-483f-8e50-40bb040b394a

    Steps:

        1. Send POST request to create new asset entity using custom python
                module
        2. Send GET request using custom python module to read just created
                 entity back.
        3. Send GET request to get type of metric/histogram endpoint
        4. Send GET request to get type of metric/topn endpoint
        5. Send GET request to get type of metric/cardinality endpoint
        6. Delete created entity
        7. Repeat GET request using python module and validate that entity was
            deleted

     Expectedresults: Asset entity can be created, fetched, researched by
         metric's endpoints and deleted using custom python module.
         Data stored in the entity is the same no matter you access it
         directly or using our tool.

    Importance: Critical
    """
    asset = module_tool_client.private_intel.asset
    payload = {
        'asset_type': 'data',
        'description': 'For Test',
        'valid_time': {
            "start_time": "2021-07-27T07:55:38.193Z",
            "end_time": "2021-07-27T07:55:38.193Z"},
        'schema_version': SERVER_VERSION,
        'source': 'test source',
        'type': 'asset',
        'short_description': 'test',
        'title': 'for test'
    }
    # Create new entity using provided payload
    post_tool_response = asset.post(payload=payload,
                                    params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'asset_type',
            'valid_time',
            'schema_version',
            'source',
            'type',
            'description',
            'short_description',
            'title'
        ]
    }
    assert values == payload
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_created_asset = asset.get(entity_id)
    assert get_created_asset['type'] == 'asset'
    assert get_created_asset['description'] == 'For Test'
    assert get_created_asset['source'] == 'test source'
    # Send GET request to get type of metric/histogram endpoint
    data_from = get_created_asset['timestamp']
    metric_histogram = asset.metric.histogram(params={'granularity': 'week',
                                                      'from': data_from,
                                                'aggregate-on': 'timestamp'})
    assert metric_histogram['type'] == 'histogram'
    # Send GET request to get type of metric/topn endpoint
    metric_topn = asset.metric.topn(params={'from': data_from,
                                                 'aggregate-on': 'asset_type'})
    assert metric_topn['type'] == 'topn'
    # Send GET request to get type of metric/cardinality endpoint
    metric_cardinality = asset.metric.cardinality(params={'from': data_from,
                                            'aggregate-on': 'asset_type'})
    assert metric_cardinality['type'] == 'cardinality'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(asset.search.delete(params={'id': entity_id,
                                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert asset.search.get(params={'id': entity_id}) == []


def test_python_module_ctia_positive_asset_mapping(
        module_headers, module_tool_client):
    """Perform testing for asset mapping entity of custom threat intelligence
     python module

    ID: CCTRI-2906 - 9f30e585-2b89-46ba-9a2d-5df8c5b91bdc

    Steps:

        1. Send POST request to create new asset entity using custom
         python module
        2. Send GET request using custom python module to read just created
            entity back.
        3. Send same GET request, but using direct access to the server
        4. Compare results
        5. Send POST request to create new asset_mapping entity using custom
         python module
        6. Send GET request using custom python module to read just created
            entity back.
        7. Send same GET request, but using direct access to the server
        8. Compare results
        9. Validate that GET request of external_id returns number of
        external_id
        10. Update asset entity using custom python module
        11. Repeat GET request using python module and validate that entity was
            updated
        12. Delete asset entity from the system
        13. Delete asset_mapping entity from the system

    Expectedresults: asset mapping entity can be created, fetched, updated and
        deleted using custom python module. Data stored in the entity is
        the same no matter you access it directly or using our tool

    Importance: Critical
    """
    asset = module_tool_client.private_intel.asset
    payload = {
        'asset_type': 'data',
        'description': 'For Test',
        'valid_time': {
            "start_time": "2021-07-27T07:55:38.193Z",
            "end_time": "2021-07-27T07:55:38.193Z"},
        'schema_version': SERVER_VERSION,
        'source': 'test source',
        'type': 'asset',
        'short_description': 'test',
        'title': 'for test',
        'external_ids': ['3']
    }
    # Create new asset entity using provided payload
    post_tool_response = asset.post(payload=payload,
                                    params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'asset_type',
            'valid_time',
            'schema_version',
            'source',
            'type',
            'description',
            'short_description',
            'title',
            'external_ids'
        ]
    }
    assert values == payload
    entity_id_asset = post_tool_response['id'].rpartition('/')[-1]
    asset_ref = post_tool_response['id']
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_tool_response = asset.get(entity_id_asset)
    get_direct_response = ctia_get_data(
        target_url=ASSET,
        entity_id=entity_id_asset,
        **{'headers': module_headers}
    ).json()
    assert get_tool_response == get_direct_response
    # Create new asset_mapping entity using provided payload
    asset_mapping = module_tool_client.private_intel.asset_mapping
    payload_values_asset_mapping = {
        'asset_type': 'data',
        'asset_ref': asset_ref,
        'confidence': 'High',
        'stability': 'Physical',
        'specificity': 'Medium',
        'valid_time': {
            "start_time": "2021-07-27T07:55:38.193Z",
            "end_time": "2021-07-27T07:55:38.193Z"},
        'schema_version': SERVER_VERSION,
        'observable': {
            'value': '1.1.1.1',
            'type': 'ip'
        },
        'source': 'test source',
        'type': 'asset-mapping',
        'external_ids': ['3']
    }
    asset_mapping_post_tool_response = asset_mapping.post(
        payload=payload_values_asset_mapping, params={'wait_for': 'true'})
    values_asset_mapping = {
        key: asset_mapping_post_tool_response[key] for key in [
            'asset_type',
            'asset_ref',
            'confidence',
            'stability',
            'specificity',
            'valid_time',
            'schema_version',
            'observable',
            'source',
            'type',
            'external_ids'
        ]
    }
    assert values_asset_mapping == payload_values_asset_mapping
    entity_id_asset_mapping = \
        asset_mapping_post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_asset_mapping_tool_response = \
        asset_mapping.get(entity_id_asset_mapping)
    get_direct_response_asset_mapping = ctia_get_data(
        target_url=ASSET_MAPPING,
        entity_id=entity_id_asset_mapping,
        **{'headers': module_headers}
    ).json()
    assert get_asset_mapping_tool_response == get_direct_response_asset_mapping
    # Validate that GET request of external_id returns number of external_ids
    external_id_result = asset_mapping.external_id(3)
    assert external_id_result[0]['external_ids'] == ['3']
    # Create expired asset mapping
    expired_asset_mapping = asset_mapping.expire(
        entity_id_asset_mapping, payload={})
    assert expired_asset_mapping['source'] == 'test source'
    # Update asset mapping entity values
    put_tool_response = delayed_return(
        asset_mapping.put(
            id_=entity_id_asset_mapping,
            payload={'asset_type': 'device',
                     'asset_ref': asset_ref,
                     'confidence': 'Low',
                     'stability': 'Temporary',
                     'specificity': 'Medium',
                     'valid_time': {
                         "start_time": "2021-07-27T07:55:38.193Z",
                         "end_time": "2021-07-27T07:55:38.193Z"},
                     'schema_version': SERVER_VERSION,
                     'observable': {
                        'value': '1.1.1.1',
                        'type': 'ip'
                                    },
                     'source': 'New test source',
                     'type': 'asset-mapping'
                     }
        )
    )
    assert put_tool_response['asset_type'] == 'device'
    get_tool_response = asset_mapping.get(entity_id_asset_mapping)
    assert get_tool_response['source'] == 'New test source'
    assert get_tool_response['asset_type'] == 'device'
    assert get_tool_response['confidence'] == 'Low'
    assert get_tool_response['stability'] == 'Temporary'
    # Delete the asset_mapping and make attempt to get it back to
    # validate it is not there anymore
    delayed_return(asset_mapping.delete(entity_id_asset_mapping))
    with pytest.raises(HTTPError):
        asset.get(entity_id_asset_mapping)
    # Delete asset entity and make attempt to get it back to
    # validate it is not there anymore
    delayed_return(asset.delete(entity_id_asset))
    with pytest.raises(HTTPError):
        asset.get(entity_id_asset)


def test_python_module_ctia_positive_asset_mapping_search(module_headers,
                                                  module_tool_client):
    """Perform testing for asset mapping/search entity of custom threat
    intelligence python module

    ID: CCTRI-2906 - 4d46be97-2134-43f7-bb09-cf7ccdb07de8

    Steps:

        1. Send POST request to create new asset entity using custom python
                module
        2. Send GET request using custom python module to read just created
                entity back.
        3. Send POST request to create new asset mapping entity using custom
         python module
        4. Send GET request using custom python module to read just created
                entity back.
        5. Count entities after entity created
        6. Delete asset mapping entity from the system
        7. Repeat GET request using python module and validate that entity was
            deleted
        8. Count entities after entity deleted
        9. Compare the amount of entities after creating and deleting entities
        10. Delete asset entity from the system

    Expectedresults: Asset mapping entity can be created, fetched, counted and
        deleted using custom python module. Data stored in the entity is
        the same no matter you access it directly or using our tool

    Importance: Critical
    """
    asset = module_tool_client.private_intel.asset
    payload = {
        'asset_type': 'data',
        'description': 'For Test',
        'valid_time': {
            "start_time": "2021-07-27T07:55:38.193Z",
            "end_time": "2021-07-27T07:55:38.193Z"},
        'schema_version': SERVER_VERSION,
        'source': 'test source',
        'type': 'asset',
        'short_description': 'test',
        'title': 'for test',
        'external_ids': ['3']
    }
    # Create new asset entity using provided payload
    post_tool_response = asset.post(payload=payload,
                                    params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'asset_type',
            'valid_time',
            'schema_version',
            'source',
            'type',
            'description',
            'short_description',
            'title',
            'external_ids'
        ]
    }
    assert values == payload
    entity_id_asset = post_tool_response['id'].rpartition('/')[-1]
    asset_ref = post_tool_response['id']
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_tool_response = asset.get(entity_id_asset)
    get_direct_response = ctia_get_data(
        target_url=ASSET,
        entity_id=entity_id_asset,
        **{'headers': module_headers}
    ).json()
    assert get_tool_response == get_direct_response
    # Create new asset_mapping entity using provided payload
    asset_mapping = module_tool_client.private_intel.asset_mapping
    payload_values_asset_mapping = {
        'asset_type': 'data',
        'asset_ref': asset_ref,
        'confidence': 'High',
        'stability': 'Physical',
        'specificity': 'Medium',
        'valid_time': {
            "start_time": "2021-07-27T07:55:38.193Z",
            "end_time": "2021-07-27T07:55:38.193Z"},
        'schema_version': SERVER_VERSION,
        'observable': {
            'value': '1.1.1.1',
            'type': 'ip'
        },
        'source': 'test source',
        'type': 'asset-mapping',
        'external_ids': ['3']
    }
    asset_mapping_post_tool_response = asset_mapping.post(
        payload=payload_values_asset_mapping, params={'wait_for': 'true'})
    values_asset_mapping = {
        key: asset_mapping_post_tool_response[key] for key in [
            'asset_type',
            'asset_ref',
            'confidence',
            'stability',
            'specificity',
            'valid_time',
            'schema_version',
            'observable',
            'source',
            'type',
            'external_ids'
        ]
    }
    assert values_asset_mapping == payload_values_asset_mapping
    entity_id_asset_mapping = \
        asset_mapping_post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_asset_mapping_search = asset_mapping.search.get(
        params={'id': entity_id_asset_mapping})
    assert get_asset_mapping_search[0]['type'] == 'asset-mapping'
    assert get_asset_mapping_search[0]['source'] == 'test source'
    # Count entities after entity created
    get_asset_mapping_search_count = asset_mapping.search.count()
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(asset_mapping.search.delete(
        params={'id': entity_id_asset_mapping,
                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert asset.search.get(params={'id': entity_id_asset_mapping}) == []
    # Count entities after entity deleted
    get_asset_mapping_search_count2 = asset_mapping.search.count()
    # Compare results of get_asset_mapping_search_count and
    # get_asset_mapping_search_count2
    assert get_asset_mapping_search_count != get_asset_mapping_search_count2
    # Delete asset entity and make attempt to get it back to
    # validate it is not there anymore
    delayed_return(asset.delete(entity_id_asset))
    with pytest.raises(HTTPError):
        asset.get(entity_id_asset)


def test_python_module_ctia_positive_asset_mapping_metric(module_headers,
                                                  module_tool_client):
    """Perform testing for asset mapping/metric endpoints of custom threat
    intelligence python module

    ID: CCTRI-2906 -6113d65c-3587-45b9-a111-f00f98719535

    Steps:

        1. Send POST request to create new asset entity using custom python
                module
        2. Send GET request using custom python module to read just created
                 entity back.
        3. Send POST request to create new asset mapping entity using custom
         python module
        4. Send GET request using custom python module to read just created
                 entity back.
        5. Send GET request to get type of metric/histogram endpoint
        6. Send GET request to get type of metric/topn endpoint
        7. Send GET request to get type of metric/cardinality endpoint
        8. Delete created entity
        9. Repeat GET request using python module and validate that entity was
            deleted
        10. Delete asset mapping entity from the system

     Expectedresults: Asset mapping entity can be created, fetched, researched
         by metric's endpoints and deleted using custom python module.
         Data stored in the entity is the same no matter you access it
         directly or using our tool.

    Importance: Critical
    """
    asset = module_tool_client.private_intel.asset
    payload = {
        'asset_type': 'data',
        'description': 'For Test',
        'valid_time': {
            "start_time": "2021-07-27T07:55:38.193Z",
            "end_time": "2021-07-27T07:55:38.193Z"},
        'schema_version': SERVER_VERSION,
        'source': 'test source',
        'type': 'asset',
        'short_description': 'test',
        'title': 'for test',
        'external_ids': ['3']
    }
    # Create new asset entity using provided payload
    post_tool_response = asset.post(payload=payload,
                                    params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'asset_type',
            'valid_time',
            'schema_version',
            'source',
            'type',
            'description',
            'short_description',
            'title',
            'external_ids'
        ]
    }
    assert values == payload
    entity_id_asset = post_tool_response['id'].rpartition('/')[-1]
    asset_ref = post_tool_response['id']
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_tool_response = asset.get(entity_id_asset)
    get_direct_response = ctia_get_data(
        target_url=ASSET,
        entity_id=entity_id_asset,
        **{'headers': module_headers}
    ).json()
    assert get_tool_response == get_direct_response
    # Create new asset_mapping entity using provided payload
    asset_mapping = module_tool_client.private_intel.asset_mapping
    payload_values_asset_mapping = {
        'asset_type': 'data',
        'asset_ref': asset_ref,
        'confidence': 'High',
        'stability': 'Physical',
        'specificity': 'Medium',
        'valid_time': {
            "start_time": "2021-07-27T07:55:38.193Z",
            "end_time": "2021-07-27T07:55:38.193Z"},
        'schema_version': SERVER_VERSION,
        'observable': {
            'value': '1.1.1.1',
            'type': 'ip'
        },
        'source': 'test source',
        'type': 'asset-mapping',
        'external_ids': ['3']
    }
    asset_mapping_post_tool_response = asset_mapping.post(
        payload=payload_values_asset_mapping, params={'wait_for': 'true'})
    values_asset_mapping = {
        key: asset_mapping_post_tool_response[key] for key in [
            'asset_type',
            'asset_ref',
            'confidence',
            'stability',
            'specificity',
            'valid_time',
            'schema_version',
            'observable',
            'source',
            'type',
            'external_ids'
        ]
    }
    assert values_asset_mapping == payload_values_asset_mapping
    entity_id_asset_mapping = \
        asset_mapping_post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_created_asset_mapping = asset_mapping.get(entity_id_asset_mapping)
    assert get_created_asset_mapping['type'] == 'asset-mapping'
    assert get_created_asset_mapping['confidence'] == 'High'
    assert get_created_asset_mapping['source'] == 'test source'
    # Send GET request to get type of metric/histogram endpoint
    data_from = get_created_asset_mapping['timestamp']
    metric_histogram = asset_mapping.metric.histogram(
        params={'granularity': 'week', 'from': data_from,
                'aggregate-on': 'timestamp'})
    assert metric_histogram['type'] == 'histogram'
    # Send GET request to get type of metric/topn endpoint
    metric_topn = asset_mapping.metric.topn(params={'from': data_from,
                                                 'aggregate-on': 'source'})
    assert metric_topn['type'] == 'topn'
    # Send GET request to get type of metric/cardinality endpoint
    metric_cardinality = asset_mapping.metric.cardinality(
        params={'from': data_from, 'aggregate-on': 'source'})
    assert metric_cardinality['type'] == 'cardinality'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(asset_mapping.search.delete(
        params={'id': entity_id_asset_mapping,
                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert asset.search.get(params={'id': entity_id_asset_mapping}) == []
    # Delete asset entity and make attempt to get it back to
    # validate it is not there anymore
    delayed_return(asset.delete(entity_id_asset))
    with pytest.raises(HTTPError):
        asset.get(entity_id_asset)


def test_python_module_ctia_positive_asset_properties(
        module_headers, module_tool_client):
    """Perform testing for asset properties entity of custom threat
     intelligence python module

    ID: CCTRI-2906 - 17265fc5-3137-4359-a396-81f214984aec

    Steps:

        1. Send POST request to create new asset entity using custom
         python module
        2. Send GET request using custom python module to read just created
            entity back.
        3. Send same GET request, but using direct access to the server
        4. Compare results
        5. Send POST request to create new asset properties entity using custom
         python module
        6. Send GET request using custom python module to read just created
            entity back.
        7. Send same GET request, but using direct access to the server
        8. Compare results
        9. Validate that GET request of external_id returns number of
        external_id
        10. Check expired endpoint
        11. Update asset entity using custom python module
        12. Repeat GET request using python module and validate that entity was
            updated
        13. Delete asset entity from the system
        14. Delete asset properties entity from the system

    Expectedresults: Asset properties entity can be created, fetched, updated
     and deleted using custom python module. Data stored in the entity is
        the same no matter you access it directly or using our tool

    Importance: Critical
    """
    asset = module_tool_client.private_intel.asset
    payload = {
        'asset_type': 'data',
        'description': 'For Test',
        'valid_time': {
            "start_time": "2021-07-27T07:55:38.193Z",
            "end_time": "2021-07-27T07:55:38.193Z"},
        'schema_version': SERVER_VERSION,
        'source': 'test source',
        'type': 'asset',
        'short_description': 'test',
        'title': 'for test',
        'external_ids': ['3']
    }
    # Create new asset entity using provided payload
    post_tool_response = asset.post(payload=payload,
                                    params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'asset_type',
            'valid_time',
            'schema_version',
            'source',
            'type',
            'description',
            'short_description',
            'title',
            'external_ids'
        ]
    }
    assert values == payload
    entity_id_asset = post_tool_response['id'].rpartition('/')[-1]
    asset_ref = post_tool_response['id']
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_tool_response = asset.get(entity_id_asset)
    get_direct_response = ctia_get_data(
        target_url=ASSET,
        entity_id=entity_id_asset,
        **{'headers': module_headers}
    ).json()
    assert get_tool_response == get_direct_response
    # Create new asset properties entity using provided payload
    asset_properties = module_tool_client.private_intel.asset_properties
    payload_values_asset_properties = {
        'asset_ref': asset_ref,
        'valid_time': {
            "start_time": "2021-07-27T07:55:38.193Z",
            "end_time": "2021-07-27T07:55:38.193Z"},
        'schema_version': SERVER_VERSION,
        'source': 'test source',
        'type': 'asset-properties',
        'external_ids': ['3']
    }
    asset_properties_post_tool_response = asset_properties.post(
        payload=payload_values_asset_properties, params={'wait_for': 'true'})
    values_asset_properties = {
        key: asset_properties_post_tool_response[key] for key in [
            'asset_ref',
            'valid_time',
            'schema_version',
            'source',
            'type',
            'external_ids'
        ]
    }
    assert values_asset_properties == payload_values_asset_properties
    entity_id_asset_properties = \
        asset_properties_post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_asset_properties_tool_response = \
        asset_properties.get(entity_id_asset_properties)
    get_direct_response_asset_properties = ctia_get_data(
        target_url=ASSET_PROPERTIES,
        entity_id=entity_id_asset_properties,
        **{'headers': module_headers}
    ).json()
    assert get_asset_properties_tool_response ==\
           get_direct_response_asset_properties
    # Validate that GET request of external_id returns number of external_ids
    external_id_result = asset_properties.external_id(3)
    assert external_id_result[0]['external_ids'] == ['3']
    # Create expired asset properties
    expired_asset_properties = asset_properties.expire(
        entity_id_asset_properties, payload={})
    assert expired_asset_properties['source'] == 'test source'
    # Update asset properties entity values
    put_tool_response = delayed_return(
        asset_properties.put(
            id_=entity_id_asset_properties,
            payload={'asset_ref': asset_ref,
                     'valid_time': {
                         "start_time": "2021-07-27T07:55:38.193Z",
                         "end_time": "2021-07-27T07:55:38.193Z"},
                     'schema_version': SERVER_VERSION,
                     'source': 'New test source',
                     'type': 'asset-properties'
                     }
        )
    )
    assert put_tool_response['type'] == 'asset-properties'
    get_tool_response = asset_properties.get(entity_id_asset_properties)
    assert get_tool_response['source'] == 'New test source'
    # Delete the asset properties and make attempt to get it back to
    # validate it is not there anymore
    delayed_return(asset_properties.delete(entity_id_asset_properties))
    with pytest.raises(HTTPError):
        asset.get(entity_id_asset_properties)
    # Delete asset entity and make attempt to get it back to
    # validate it is not there anymore
    delayed_return(asset.delete(entity_id_asset))
    with pytest.raises(HTTPError):
        asset.get(entity_id_asset)


def test_python_module_ctia_positive_asset_properties_search(module_headers,
                                                  module_tool_client):
    """Perform testing for asset properties/search entity of custom threat
    intelligence python module

    ID: CCTRI-2906 - 3246f737-e33d-4e60-b21f-3a85c28eddcf

    Steps:

        1. Send POST request to create new asset entity using custom python
                module
        2. Send GET request using custom python module to read just created
                entity back.
        3. Send POST request to create new asset properties entity using custom
         python module
        4. Send GET request using custom python module to read just created
                entity back.
        5. Count entities after entity created
        6. Delete asset properties entity from the system
        7. Repeat GET request using python module and validate that entity was
            deleted
        8. Count entities after entity deleted
        9. Compare the amount of entities after creating and deleting entities
        10. Delete asset entity from the system

    Expectedresults: Asset properties entity can be created, fetched, counted
     and deleted using custom python module. Data stored in the entity is
        the same no matter you access it directly or using our tool

    Importance: Critical
    """
    asset = module_tool_client.private_intel.asset
    payload = {
        'asset_type': 'data',
        'description': 'For Test',
        'valid_time': {
            "start_time": "2021-07-27T07:55:38.193Z",
            "end_time": "2021-07-27T07:55:38.193Z"},
        'schema_version': SERVER_VERSION,
        'source': 'test source',
        'type': 'asset',
        'short_description': 'test',
        'title': 'for test',
        'external_ids': ['3']
    }
    # Create new asset entity using provided payload
    post_tool_response = asset.post(payload=payload,
                                    params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'asset_type',
            'valid_time',
            'schema_version',
            'source',
            'type',
            'description',
            'short_description',
            'title',
            'external_ids'
        ]
    }
    assert values == payload
    entity_id_asset = post_tool_response['id'].rpartition('/')[-1]
    asset_ref = post_tool_response['id']
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_tool_response = asset.get(entity_id_asset)
    get_direct_response = ctia_get_data(
        target_url=ASSET,
        entity_id=entity_id_asset,
        **{'headers': module_headers}
    ).json()
    assert get_tool_response == get_direct_response
    # Create new asset properties entity using provided payload
    asset_properties = module_tool_client.private_intel.asset_properties
    payload_values_asset_properties = {
        'asset_ref': asset_ref,
        'valid_time': {
            "start_time": "2021-07-27T07:55:38.193Z",
            "end_time": "2021-07-27T07:55:38.193Z"},
        'schema_version': SERVER_VERSION,
        'source': 'test source',
        'type': 'asset-properties',
        'external_ids': ['3']
    }
    asset_properties_post_tool_response = asset_properties.post(
        payload=payload_values_asset_properties, params={'wait_for': 'true'})
    values_asset_properties = {
        key: asset_properties_post_tool_response[key] for key in [
            'asset_ref',
            'valid_time',
            'schema_version',
            'source',
            'type',
            'external_ids'
        ]
    }
    assert values_asset_properties == payload_values_asset_properties
    entity_id_asset_properties = \
        asset_properties_post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_asset_properties_search = asset_properties.search.get(
        params={'id': entity_id_asset_properties})
    assert get_asset_properties_search[0]['type'] == 'asset-properties'
    assert get_asset_properties_search[0]['source'] == 'test source'
    # Count entities after entity created
    get_asset_properties_search_count = asset_properties.search.count()
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(asset_properties.search.delete(
        params={'id': entity_id_asset_properties,
                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert asset.search.get(params={'id': entity_id_asset_properties}) == []
    # Count entities after entity deleted
    get_asset_properties_search_count2 = asset_properties.search.count()
    # Compare results of get_asset_properties_search_count and
    # get_asset_properties_search_count2
    assert get_asset_properties_search_count != \
           get_asset_properties_search_count2
    # Delete asset entity and make attempt to get it back to
    # validate it is not there anymore
    delayed_return(asset.delete(entity_id_asset))
    with pytest.raises(HTTPError):
        asset.get(entity_id_asset)


def test_python_module_ctia_positive_asset_properties_metric(module_headers,
                                                  module_tool_client):
    """Perform testing for asset properties/metric endpoints of custom threat
    intelligence python module

    ID: CCTRI-2906 -b3c835e4-4c5d-4d5d-95f6-45d3d7e350c3

    Steps:

        1. Send POST request to create new asset entity using custom python
                module
        2. Send GET request using custom python module to read just created
                 entity back.
        3. Send POST request to create new asset properties entity using custom
         python module
        4. Send GET request using custom python module to read just created
                 entity back.
        5. Send GET request to get type of metric/histogram endpoint
        6. Send GET request to get type of metric/topn endpoint
        7. Send GET request to get type of metric/cardinality endpoint
        8. Delete created entity
        9. Repeat GET request using python module and validate that entity was
            deleted
        10. Delete asset properties entity from the system

     Expectedresults: Asset propertis entity can be created, fetched,
      researched by metric's endpoints and deleted using custom python module.
         Data stored in the entity is the same no matter you access it
         directly or using our tool.

    Importance: Critical
    """
    asset = module_tool_client.private_intel.asset
    payload = {
        'asset_type': 'data',
        'description': 'For Test',
        'valid_time': {
            "start_time": "2021-07-27T07:55:38.193Z",
            "end_time": "2021-07-27T07:55:38.193Z"},
        'schema_version': SERVER_VERSION,
        'source': 'test source',
        'type': 'asset',
        'short_description': 'test',
        'title': 'for test',
        'external_ids': ['3']
    }
    # Create new asset entity using provided payload
    post_tool_response = asset.post(payload=payload,
                                    params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'asset_type',
            'valid_time',
            'schema_version',
            'source',
            'type',
            'description',
            'short_description',
            'title',
            'external_ids'
        ]
    }
    assert values == payload
    entity_id_asset = post_tool_response['id'].rpartition('/')[-1]
    asset_ref = post_tool_response['id']
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_tool_response = asset.get(entity_id_asset)
    get_direct_response = ctia_get_data(
        target_url=ASSET,
        entity_id=entity_id_asset,
        **{'headers': module_headers}
    ).json()
    assert get_tool_response == get_direct_response
    # Create new asset properties entity using provided payload
    asset_properties = module_tool_client.private_intel.asset_properties
    payload_values_asset_properties = {
        'asset_ref': asset_ref,
        'valid_time': {
            "start_time": "2021-07-27T07:55:38.193Z",
            "end_time": "2021-07-27T07:55:38.193Z"},
        'schema_version': SERVER_VERSION,
        'source': 'test source',
        'type': 'asset-properties',
        'external_ids': ['3']
    }
    asset_properties_post_tool_response = asset_properties.post(
        payload=payload_values_asset_properties, params={'wait_for': 'true'})
    values_asset_properties = {
        key: asset_properties_post_tool_response[key] for key in [
            'asset_ref',
            'valid_time',
            'schema_version',
            'source',
            'type',
            'external_ids'
        ]
    }
    assert values_asset_properties == payload_values_asset_properties
    entity_id_asset_properties = \
        asset_properties_post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_created_asset_properties = \
        asset_properties.get(entity_id_asset_properties)
    assert get_created_asset_properties['type'] == 'asset-properties'
    assert get_created_asset_properties['source'] == 'test source'
    # Send GET request to get type of metric/histogram endpoint
    data_from = get_created_asset_properties['timestamp']
    metric_histogram = asset_properties.metric.histogram(
        params={'granularity': 'week', 'from': data_from,
                'aggregate-on': 'timestamp'})
    assert metric_histogram['type'] == 'histogram'
    # Send GET request to get type of metric/topn endpoint
    metric_topn = asset_properties.metric.topn(params={'from': data_from,
                                                 'aggregate-on': 'source'})
    assert metric_topn['type'] == 'topn'
    # Send GET request to get type of metric/cardinality endpoint
    metric_cardinality = asset_properties.metric.cardinality(
        params={'from': data_from, 'aggregate-on': 'source'})
    assert metric_cardinality['type'] == 'cardinality'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(asset_properties.search.delete(
        params={'id': entity_id_asset_properties,
                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert asset.search.get(params={'id': entity_id_asset_properties}) == []
    # Delete asset entity and make attempt to get it back to
    # validate it is not there anymore
    delayed_return(asset.delete(entity_id_asset))
    with pytest.raises(HTTPError):
        asset.get(entity_id_asset)


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
        'schema_version': SERVER_VERSION,
        'type': 'attack-pattern',
        'short_description': 'desc for test',
        'source': 'new source point',
        'title': 'for test'
    }
    # Create new entity using provided payload
    post_tool_response = attack_pattern.post(payload=payload,
                                             params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'description',
            'schema_version',
            'type',
            'short_description',
            'source',
            'title'
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
                'short_description': 'Updated descr',
                'description': (
                    'A standalone malware that replicates itself in order to'
                    ' spread to other computers'
                ),
                'title': 'for test'
            }
        )
    )
    assert put_tool_response['short_description'] == 'Updated descr'
    get_tool_response = attack_pattern.get(entity_id)
    assert get_tool_response['short_description'] == 'Updated descr'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(attack_pattern.delete(entity_id))
    with pytest.raises(HTTPError):
        attack_pattern.get(entity_id)


def test_python_module_ctia_positive_attack_pattern_search(module_headers,
                                                  module_tool_client):
    """Perform testing for attack_pattern/search entity of custom threat
    intelligence python module

    ID: CCTRI-2848 - 642bcca5-3eec-4955-b395-e4c365b65bf5

    Steps:

        1. Send POST request to create new attack_pattern entity using
        custom python module
        2. Send GET request using custom python module to read just created
                entity back.
        3. Count entities after entity created
        4. Delete entity from the system
        5. Repeat GET request using python module and validate that entity was
            deleted
        6. Count entities after entity deleted
        7. Compare the amount of entities after creating and deleting entities

    Expectedresults: attack_pattern entity can be created, fetched, counted and
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

        'schema_version': SERVER_VERSION,
        'type': 'attack-pattern',
        'short_description': 'desc for test',
        'source': 'new source point',

        'title': 'for test'

    }
    # Create new entity using provided payload
    post_tool_response = attack_pattern.post(payload=payload,
                                             params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'description',
            'schema_version',
            'type',
            'short_description',
            'source',
            'title'
        ]
    }
    assert values == payload
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_attack_pattern_search = attack_pattern.search.get(
        params={'id': entity_id})
    assert get_attack_pattern_search[0]['type'] == 'attack-pattern'
    assert get_attack_pattern_search[0]['schema_version'] == '1.1.3'
    # Count entities after entity created
    get_attack_pattern_search_count = attack_pattern.search.count()
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(attack_pattern.search.delete(params={'id': entity_id,
                                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert attack_pattern.search.get(params={'id': entity_id}) == []
    # Count entities after entity deleted
    get_attack_pattern_search_count2 = attack_pattern.search.count()
    # Compare results of get_attack_pattern_search_count
    # and get_attack_pattern_search_count2
    assert get_attack_pattern_search_count != get_attack_pattern_search_count2


def test_python_module_ctia_positive_attack_pattern_metric(module_headers,
                                                  module_tool_client):
    """Perform testing for attack_pattern/metric endpoints of custom threat
    intelligence python module

    ID: CCTRI-2848 -1b6c327c-cf55-4e22-a72c-93f9ad4b2763

    Steps:

        1. Send POST request to create new attack_pattern entity using
        custom python module
        2. Send GET request using custom python module to read just created
                 entity back.
        3. Send GET request to get type of metric/histogram endpoint
        4. Send GET request to get type of metric/topn endpoint
        5. Send GET request to get type of metric/cardinality endpoint
        6. Delete created entity
        7. Repeat GET request using python module and validate that entity was
            deleted

     Expectedresults: attack_pattern entity can be created, fetched,
     researched by metric's endpoints and deleted using custom python module.
     Data stored in the entity is the same no matter you access it
     directly or using our tool.

    Importance: Critical
    """
    attack_pattern = module_tool_client.private_intel.attack_pattern
    payload = {
        'description': (
            'A bootkit is a malware variant that modifies the boot sectors of'
            ' a hard drive'
        ),

        'schema_version': SERVER_VERSION,
        'type': 'attack-pattern',
        'short_description': 'desc for test',
        'source': 'new source point',

        'title': 'for test'

    }
    # Create new entity using provided payload
    post_tool_response = attack_pattern.post(payload=payload,
                                             params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'description',
            'schema_version',
            'type',
            'short_description',
            'source',
            'title'
        ]
    }
    assert values == payload
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_created_attack_pattern = attack_pattern.get(entity_id)
    assert get_created_attack_pattern['type'] == 'attack-pattern'
    assert get_created_attack_pattern['schema_version'] == '1.1.3'
    # Send GET request to get type of metric/histogram endpoint
    data_from = get_created_attack_pattern['timestamp']
    metric_histogram = attack_pattern.metric.histogram(params={
        'granularity': 'week', 'from': data_from, 'aggregate-on': 'timestamp'})
    assert metric_histogram['type'] == 'histogram'
    # Send GET request to get type of metric/topn endpoint
    metric_topn = attack_pattern.metric.topn(params={'from': data_from,
                                                 'aggregate-on': 'source'})
    assert metric_topn['type'] == 'topn'
    # Send GET request to get type of metric/cardinality endpoint
    metric_cardinality = attack_pattern.metric.cardinality(params={
        'from': data_from, 'aggregate-on': 'source'})
    assert metric_cardinality['type'] == 'cardinality'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(attack_pattern.search.delete(params={'id': entity_id,
                                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert attack_pattern.search.get(params={'id': entity_id}) == []


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
        'schema_version': SERVER_VERSION,
        'description': 'For test',
        'short_description': 'Short test description',
        'title': 'Test'
    }
    coa_payload = {
        'description': 'COA entity we use for bulk testing',
        'coa_type': 'Diplomatic Actions',
        'type': 'coa',
        'schema_version': SERVER_VERSION,
        'short_description': 'Short test description',
        'title': 'Test'
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
            'schema_version',
            'description',
            'short_description',
            'title'
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
    assert post_tool_response['indicators'][0]['id'] == (
        indicator_post_response['id']
    )
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
        'schema_version': SERVER_VERSION,
        'description': 'For Test',
        'short_description': 'Short test description'
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
            'schema_version',
            'description',
            'short_description'
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
            payload={'title': 'New demo campaign',
                     'campaign_type': 'Critical',
                     'description': 'For Test',
                     'short_description': 'Short test description'
                     }
        )
    )
    assert put_tool_response['title'] == 'New demo campaign'
    get_tool_response = campaign.get(entity_id)
    assert get_tool_response['title'] == 'New demo campaign'
    # Search for campaign by entity id
    search_tool_response = campaign.search.get(params={
        'query': 'id:*{}'.format(entity_id)})
    # We got exactly one entry for provided unique entity id
    assert len(search_tool_response) == 1
    assert search_tool_response[0]['title'] == 'New demo campaign'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(campaign.delete(entity_id))
    with pytest.raises(HTTPError):
        campaign.get(entity_id)


def test_python_module_ctia_positive_campaign_search(module_headers,
                                                  module_tool_client):
    """Perform testing for campaign/search entity of custom threat
    intelligence python module

    ID: CCTRI-2848 - b65fb933-d81b-4189-abbb-849fc2deef06

    Steps:

        1. Send POST request to create new campaign entity using
        custom python module
        2. Send GET request using custom python module to read just created
                entity back.
        3. Count entities after entity created
        4. Delete entity from the system
        5. Repeat GET request using python module and validate that entity was
            deleted
        6. Count entities after entity deleted
        7. Compare the amount of entities after creating and deleting entities

    Expectedresults: campaign entity can be created, fetched, counted and
        deleted using custom python module. Data stored in the entity is
        the same no matter you access it directly or using our tool

    Importance: Critical
    """
    campaign = module_tool_client.private_intel.campaign
    payload = {
        'title': 'Demo campaign',
        'campaign_type': 'Critical',
        'confidence': 'Medium',
        'type': 'campaign',
        'schema_version': SERVER_VERSION,
        'description': 'For Test',
        'short_description': 'Short test description'
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
            'schema_version',
            'description',
            'short_description'
        ]
    }
    assert values == payload
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_campaign_search = campaign.search.get(
        params={'id': entity_id})
    assert get_campaign_search[0]['type'] == 'campaign'
    assert get_campaign_search[0]['schema_version'] == '1.1.3'
    # Count entities after entity created
    get_campaign_search_count = campaign.search.count()
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(campaign.search.delete(params={'id': entity_id,
                                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert campaign.search.get(params={'id': entity_id}) == []
    # Count entities after entity deleted
    get_campaign_search_count2 = campaign.search.count()
    # Compare results of get_campaign_search_count
    # and get_campaign_search_count2
    assert get_campaign_search_count != get_campaign_search_count2


def test_python_module_ctia_positive_campaign_metric(module_headers,
                                                  module_tool_client):
    """Perform testing for campaign/metric endpoints of custom threat
    intelligence python module

    ID: CCTRI-2848 -b11cbee0-a3e5-4a19-8b4a-d3d16e7bfb5c

    Steps:

        1. Send POST request to create new campaign entity using
        custom python module
        2. Send GET request using custom python module to read just created
                 entity back.
        3. Send GET request to get type of metric/histogram endpoint
        4. Send GET request to get type of metric/topn endpoint
        5. Send GET request to get type of metric/cardinality endpoint
        6. Delete created entity
        7. Repeat GET request using python module and validate that entity was
            deleted

     Expectedresults: campaign entity can be created, fetched,
     researched by metric's endpoints and deleted using custom python module.
     Data stored in the entity is the same no matter you access it
     directly or using our tool.

    Importance: Critical
    """
    campaign = module_tool_client.private_intel.campaign
    payload = {
        'title': 'Demo campaign',
        'campaign_type': 'Critical',
        'confidence': 'Medium',
        'type': 'campaign',
        'schema_version': SERVER_VERSION,
        'description': 'For Test',
        'short_description': 'Short test description'
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
            'schema_version',
            'description',
            'short_description'
        ]
    }
    assert values == payload
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_created_campaign = campaign.get(entity_id)
    assert get_created_campaign['type'] == 'campaign'
    assert get_created_campaign['schema_version'] == '1.1.3'
    # Send GET request to get type of metric/histogram endpoint
    data_from = get_created_campaign['timestamp']
    metric_histogram = campaign.metric.histogram(params={
        'granularity': 'week', 'from': data_from, 'aggregate-on': 'timestamp'})
    assert metric_histogram['type'] == 'histogram'
    # Send GET request to get type of metric/topn endpoint
    metric_topn = campaign.metric.topn(params={'from': data_from,
                                                 'aggregate-on': 'source'})
    assert metric_topn['type'] == 'topn'
    # Send GET request to get type of metric/cardinality endpoint
    metric_cardinality = campaign.metric.cardinality(params={
        'from': data_from, 'aggregate-on': 'source'})
    assert metric_cardinality['type'] == 'cardinality'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(campaign.search.delete(params={'id': entity_id,
                                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert campaign.search.get(params={'id': entity_id}) == []


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
        9. Use Patch endpoint for updating updated entity
        10. Delete entity from the system

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
    # Use Patch endpoint for updating updated entity
    payload_for_patch = {
        'type': 'casebook',
        'title': 'Case November, 2021 0:00 PM',
        'short_description': 'Patched Casebook',
        'description': 'Patched entity',
        'observables': [],
        'timestamp': '2019-09-24T11:34:18.000Z'
    }
    patch_tool_response = casebook.patch(entity_id, payload=payload_for_patch,
                                         params={'wait_for': 'true'})
    assert patch_tool_response['short_description'] == 'Patched Casebook'
    assert patch_tool_response['description'] == 'Patched entity'
    assert patch_tool_response['title'] == 'Case November, 2021 0:00 PM'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(casebook.delete(entity_id))
    with pytest.raises(HTTPError):
        casebook.get(entity_id)


def test_python_module_ctia_positive_casebook_search(module_headers,
                                                  module_tool_client):
    """Perform testing for casebook/search entity of custom threat
    intelligence python module

    ID: CCTRI-2848 - 90719039-6d18-49cf-87fb-739e695be1fd

    Steps:

        1. Send POST request to create new casebook entity using
        custom python module
        2. Send GET request using custom python module to read just created
                entity back.
        3. Count entities after entity created
        4. Delete entity from the system
        5. Repeat GET request using python module and validate that entity was
            deleted
        6. Count entities after entity deleted
        7. Compare the amount of entities after creating and deleting entities

    Expectedresults: casebook entity can be created, fetched, counted and
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
        'observables': observable,
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
    get_casebook_search = casebook.search.get(
        params={'id': entity_id})
    assert get_casebook_search[0]['type'] == 'casebook'
    assert get_casebook_search[0]['schema_version'] == '1.1.3'
    # Count entities after entity created
    get_casebook_search_count = casebook.search.count()
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(casebook.search.delete(params={'id': entity_id,
                                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert casebook.search.get(params={'id': entity_id}) == []
    # Count entities after entity deleted
    get_casebook_search_count2 = casebook.search.count()
    # Compare results of get_casebook_search_count
    # and get_casebook_search_count2
    assert get_casebook_search_count != get_casebook_search_count2


def test_python_module_ctia_positive_casebook_metric(module_headers,
                                                  module_tool_client):
    """Perform testing for casebook/metric endpoints of custom threat
    intelligence python module

    ID: CCTRI-2848 -e5f86888-5cab-4048-ae5a-92220db88497

    Steps:

        1. Send POST request to create new casebook entity using
        custom python module
        2. Send GET request using custom python module to read just created
                 entity back.
        3. Send GET request to get type of metric/histogram endpoint
        4. Send GET request to get type of metric/topn endpoint
        5. Send GET request to get type of metric/cardinality endpoint
        6. Delete created entity
        7. Repeat GET request using python module and validate that entity was
            deleted

     Expectedresults: casebook entity can be created, fetched,
     researched by metric's endpoints and deleted using custom python module.
     Data stored in the entity is the same no matter you access it
     directly or using our tool.

    Importance: Critical
    """
    casebook = module_tool_client.private_intel.casebook
    observable = [{'value': 'instanbul.com', 'type': 'domain'}]
    payload = {
        'type': 'casebook',
        'title': 'Case September 24, 2019 2:34 PM',
        'short_description': 'New Casebook',
        'description': 'New Casebook for malicious tickets',
        'observables': observable,
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
    get_created_casebook = casebook.get(entity_id)
    assert get_created_casebook['type'] == 'casebook'
    assert get_created_casebook['schema_version'] == '1.1.3'
    # Send GET request to get type of metric/histogram endpoint
    data_from = get_created_casebook['timestamp']
    metric_histogram = casebook.metric.histogram(params={
        'granularity': 'week', 'from': data_from, 'aggregate-on': 'timestamp'})
    assert metric_histogram['type'] == 'histogram'
    # Send GET request to get type of metric/topn endpoint
    metric_topn = casebook.metric.topn(params={'from': data_from,
                                                 'aggregate-on': 'source'})
    assert metric_topn['type'] == 'topn'
    # Send GET request to get type of metric/cardinality endpoint
    metric_cardinality = casebook.metric.cardinality(params={
        'from': data_from, 'aggregate-on': 'source'})
    assert metric_cardinality['type'] == 'cardinality'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(casebook.search.delete(params={'id': entity_id,
                                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert casebook.search.get(params={'id': entity_id}) == []


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


def test_python_module_ctia_positive_coa_search(module_headers,
                                                  module_tool_client):
    """Perform testing for coa/search entity of custom threat
    intelligence python module

    ID: CCTRI-2848 - 5bd4220c-f91f-407d-9b3b-c436d8dc5c3f

    Steps:

        1. Send POST request to create new coa entity using
        custom python module
        2. Send GET request using custom python module to read just created
                entity back.
        3. Count entities after entity created
        4. Delete entity from the system
        5. Repeat GET request using python module and validate that entity was
            deleted
        6. Count entities after entity deleted
        7. Compare the amount of entities after creating and deleting entities

    Expectedresults: coa entity can be created, fetched, counted and
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
    get_coa_search = coa.search.get(
        params={'id': entity_id})
    assert get_coa_search[0]['type'] == 'coa'
    assert get_coa_search[0]['schema_version'] == '1.1.3'
    # Count entities after entity created
    get_coa_search_count = coa.search.count()
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(coa.search.delete(params={'id': entity_id,
                                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert coa.search.get(params={'id': entity_id}) == []
    # Count entities after entity deleted
    get_coa_search_count2 = coa.search.count()
    # Compare results of get_coa_search_count
    # and get_coa_search_count2
    assert get_coa_search_count != get_coa_search_count2


def test_python_module_ctia_positive_coa_metric(module_headers,
                                                  module_tool_client):
    """Perform testing for coa/metric endpoints of custom threat
    intelligence python module

    ID: CCTRI-2848 -73e26197-527f-437b-9ad8-eb5cd34761ed

    Steps:

        1. Send POST request to create new coa entity using
        custom python module
        2. Send GET request using custom python module to read just created
                 entity back.
        3. Send GET request to get type of metric/histogram endpoint
        4. Send GET request to get type of metric/topn endpoint
        5. Send GET request to get type of metric/cardinality endpoint
        6. Delete created entity
        7. Repeat GET request using python module and validate that entity was
            deleted

     Expectedresults: coa entity can be created, fetched,
     researched by metric's endpoints and deleted using custom python module.
     Data stored in the entity is the same no matter you access it
     directly or using our tool.

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
    get_created_coa = coa.get(entity_id)
    assert get_created_coa['type'] == 'coa'
    assert get_created_coa['schema_version'] == '1.1.3'
    # Send GET request to get type of metric/histogram endpoint
    data_from = get_created_coa['timestamp']
    metric_histogram = coa.metric.histogram(params={
        'granularity': 'week', 'from': data_from, 'aggregate-on': 'timestamp'})
    assert metric_histogram['type'] == 'histogram'
    # Send GET request to get type of metric/topn endpoint
    metric_topn = coa.metric.topn(params={'from': data_from,
                                                 'aggregate-on': 'source'})
    assert metric_topn['type'] == 'topn'
    # Send GET request to get type of metric/cardinality endpoint
    metric_cardinality = coa.metric.cardinality(params={
        'from': data_from, 'aggregate-on': 'source'})
    assert metric_cardinality['type'] == 'cardinality'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(coa.search.delete(params={'id': entity_id,
                                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert coa.search.get(params={'id': entity_id}) == []


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
    entities_list = event.search.get(params={'query': '*'})
    assert len(entities_list) > 0
    entity = random.choice(entities_list)
    assert entity['type'] == 'event'
    get_tool_response = event.get(entity['id'].rpartition('/')[-1])
    assert get_tool_response['type'] == 'event'
    assert get_tool_response['timestamp']


def test_python_module_ctia_positive_event_search(module_headers,
                                                  module_tool_client):
    """Perform testing for event/search entity of custom threat
    intelligence python module

    ID: CCTRI-2906 - 363a43d4-1862-4eed-aecb-3d011804642d

    Steps:

        1. Send GET request using custom python module to read just created
                entity back.
        2. Count entities after entity created
        3. Delete entity from the system
        4. Count entities after entity deleted
        5. Compare the amount of entities after creating and deleting entities

    Expectedresults: Event entity can be fetched, counted and
        deleted using custom python module. Data stored in the entity is
        the same no matter you access it directly or using our tool

    Importance: Critical
    """
    event = module_tool_client.private_intel.event
    # Validate that GET request return same data for direct access and access
    # through custom python module
    event_search = event.search.get()
    assert event_search[1]['type'] == 'event'
    entity_id = event_search[1]['id'].rpartition('/')[-1]
    # Count entities after entity created
    get_event_search_count = event.search.count()
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    deleting_response = None
    try:
        event.search.delete(params={
            'id': entity_id, 'REALLY_DELETE_ALL_THESE_ENTITIES': 'true',
            'wait_for': 'true'})
    except HTTPError as error:
        deleting_response = error
    assert deleting_response.response.status_code == 403
    json_string = deleting_response.response.text
    parsed_text_response = json.loads(json_string)
    assert parsed_text_response['message'] == 'Missing capability'
    assert parsed_text_response['error'] == 'missing_capability'
    assert parsed_text_response['capabilities'][0] == 'search-event'
    assert parsed_text_response['capabilities'][1] == 'developer'
    assert parsed_text_response['capabilities'][2] == 'delete-event'
    # Count entities after entity deleted
    get_event_search_count2 = event.search.count()
    # Compare results of get_event_search_count
    # and get_event_search_count2
    assert get_event_search_count == get_event_search_count2


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
        'schema_version': SERVER_VERSION,
        'description': "for test",
        'short_description': 'sort test description',
        'title': 'Test title'
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


def test_python_module_ctia_positive_incident_search(module_headers,
                                                  module_tool_client):
    """Perform testing for incident/search entity of custom threat
    intelligence python module

    ID: CCTRI-2848 - 8fc6ba46-a610-4432-a72b-af92836fa560

    Steps:

        1. Send POST request to create new incident entity using
        custom python module
        2. Send GET request using custom python module to read just created
                entity back.
        3. Count entities after entity created
        4. Delete entity from the system
        5. Repeat GET request using python module and validate that entity was
            deleted
        6. Count entities after entity deleted
        7. Compare the amount of entities after creating and deleting entities

    Expectedresults: incident entity can be created, fetched, counted and
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
    get_incident_search = incident.search.get(
        params={'id': entity_id})
    assert get_incident_search[0]['type'] == 'incident'
    assert get_incident_search[0]['schema_version'] == '1.1.3'
    # Count entities after entity created
    get_incident_search_count = incident.search.count()
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(incident.search.delete(params={'id': entity_id,
                                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert incident.search.get(params={'id': entity_id}) == []
    # Count entities after entity deleted
    get_incident_search_count2 = incident.search.count()
    # Compare results of get_incident_search_count
    # and get_incident_search_count2
    assert get_incident_search_count != get_incident_search_count2


def test_python_module_ctia_positive_incident_metric(module_headers,
                                                  module_tool_client):
    """Perform testing for incident/metric endpoints of custom threat
    intelligence python module

    ID: CCTRI-2848 -1828964e-ebee-4ed5-939f-f44e8010e0eb

    Steps:

        1. Send POST request to create new incident entity using
        custom python module
        2. Send GET request using custom python module to read just created
                 entity back.
        3. Send GET request to get type of metric/histogram endpoint
        4. Send GET request to get type of metric/topn endpoint
        5. Send GET request to get type of metric/cardinality endpoint
        6. Delete created entity
        7. Repeat GET request using python module and validate that entity was
            deleted

     Expectedresults: incident entity can be created, fetched,
     researched by metric's endpoints and deleted using custom python module.
     Data stored in the entity is the same no matter you access it
     directly or using our tool.

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
    get_created_incident = incident.get(entity_id)
    assert get_created_incident['type'] == 'incident'
    assert get_created_incident['schema_version'] == '1.1.3'
    # Send GET request to get type of metric/histogram endpoint
    data_from = get_created_incident['timestamp']
    metric_histogram = incident.metric.histogram(params={
        'granularity': 'week', 'from': data_from, 'aggregate-on': 'timestamp'})
    assert metric_histogram['type'] == 'histogram'
    # Send GET request to get type of metric/topn endpoint
    metric_topn = incident.metric.topn(params={'from': data_from,
                                                 'aggregate-on': 'source'})
    assert metric_topn['type'] == 'topn'
    # Send GET request to get type of metric/cardinality endpoint
    metric_cardinality = incident.metric.cardinality(params={
        'from': data_from, 'aggregate-on': 'source'})
    assert metric_cardinality['type'] == 'cardinality'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(incident.search.delete(params={'id': entity_id,
                                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert incident.search.get(params={'id': entity_id}) == []


def test_python_module_ctia_positive_indicator(
        module_headers, module_tool_client):
    """Perform testing for indicator entity of custom threat intelligence
     python module

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


def test_python_module_ctia_positive_indicator_search(module_headers,
                                                  module_tool_client):
    """Perform testing for indicator/search entity of custom threat
    intelligence python module

    ID: CCTRI-2848 - 6137f999-74e9-456e-bea8-42f26341de43

    Steps:

        1. Send POST request to create new indicator entity using
        custom python module
        2. Send GET request using custom python module to read just created
                entity back.
        3. Count entities after entity created
        4. Delete entity from the system
        5. Repeat GET request using python module and validate that entity was
            deleted
        6. Count entities after entity deleted
        7. Compare the amount of entities after creating and deleting entities

    Expectedresults: indicator entity can be created, fetched, counted and
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
    get_indicator_search = indicator.search.get(
        params={'id': entity_id})
    assert get_indicator_search[0]['type'] == 'indicator'
    assert get_indicator_search[0]['schema_version'] == '1.1.3'
    # Count entities after entity created
    get_indicator_search_count = indicator.search.count()
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(indicator.search.delete(params={'id': entity_id,
                                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert indicator.search.get(params={'id': entity_id}) == []
    # Count entities after entity deleted
    get_indicator_search_count2 = indicator.search.count()
    # Compare results of get_indicator_search_count
    # and get_indicator_search_count2
    assert get_indicator_search_count != get_indicator_search_count2


def test_python_module_ctia_positive_indicator_metric(module_headers,
                                                  module_tool_client):
    """Perform testing for indicator/metric endpoints of custom threat
    intelligence python module

    ID: CCTRI-2848 -36009d09-8efc-412d-8003-33fb148ba8bf

    Steps:

        1. Send POST request to create new indicator entity using
        custom python module
        2. Send GET request using custom python module to read just created
                 entity back.
        3. Send GET request to get type of metric/histogram endpoint
        4. Send GET request to get type of metric/topn endpoint
        5. Send GET request to get type of metric/cardinality endpoint
        6. Delete created entity
        7. Repeat GET request using python module and validate that entity was
            deleted

     Expectedresults: indicator entity can be created, fetched,
     researched by metric's endpoints and deleted using custom python module.
     Data stored in the entity is the same no matter you access it
     directly or using our tool.

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
    get_created_indicator = indicator.get(entity_id)
    assert get_created_indicator['type'] == 'indicator'
    assert get_created_indicator['schema_version'] == '1.1.3'
    # Send GET request to get type of metric/histogram endpoint
    data_from = get_created_indicator['timestamp']
    metric_histogram = indicator.metric.histogram(params={
        'granularity': 'week', 'from': data_from, 'aggregate-on': 'timestamp'})
    assert metric_histogram['type'] == 'histogram'
    # Send GET request to get type of metric/topn endpoint
    metric_topn = indicator.metric.topn(params={'from': data_from,
                                                 'aggregate-on': 'source'})
    assert metric_topn['type'] == 'topn'
    # Send GET request to get type of metric/cardinality endpoint
    metric_cardinality = indicator.metric.cardinality(params={
        'from': data_from, 'aggregate-on': 'source'})
    assert metric_cardinality['type'] == 'cardinality'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(indicator.search.delete(params={'id': entity_id,
                                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert indicator.search.get(params={'id': entity_id}) == []


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


def test_python_module_ctia_positive_investigation_search(module_headers,
                                                  module_tool_client):
    """Perform testing for investigation/search entity of custom threat
    intelligence python module

    ID: CCTRI-2848 - 7dae9799-2ae0-4a8c-81ae-99477bb4833a

    Steps:

        1. Send POST request to create new investigation entity using
        custom python module
        2. Send GET request using custom python module to read just created
                entity back.
        3. Count entities after entity created
        4. Delete entity from the system
        5. Repeat GET request using python module and validate that entity was
            deleted
        6. Count entities after entity deleted
        7. Compare the amount of entities after creating and deleting entities

    Expectedresults: investigation entity can be created, fetched, counted and
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
    get_investigation_search = investigation.search.get(
        params={'id': entity_id})
    assert get_investigation_search[0]['type'] == 'investigation'
    assert get_investigation_search[0]['schema_version'] == '1.1.3'
    # Count entities after entity created
    get_investigation_search_count = investigation.search.count()
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(investigation.search.delete(params={'id': entity_id,
                                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert investigation.search.get(params={'id': entity_id}) == []
    # Count entities after entity deleted
    get_investigation_search_count2 = investigation.search.count()
    # Compare results of get_investigation_search_count
    # and get_investigation_search_count2
    assert get_investigation_search_count != get_investigation_search_count2


def test_python_module_ctia_positive_investigation_metric(module_headers,
                                                  module_tool_client):
    """Perform testing for investigation/metric endpoints of custom threat
    intelligence python module

    ID: CCTRI-2848 -b1148fab-b57e-409c-a6b4-2ce0bd229bf1

    Steps:

        1. Send POST request to create new investigation entity using
        custom python module
        2. Send GET request using custom python module to read just created
                 entity back.
        3. Send GET request to get type of metric/histogram endpoint
        4. Send GET request to get type of metric/topn endpoint
        5. Send GET request to get type of metric/cardinality endpoint
        6. Delete created entity
        7. Repeat GET request using python module and validate that entity was
            deleted

     Expectedresults: investigation entity can be created, fetched,
     researched by metric's endpoints and deleted using custom python module.
     Data stored in the entity is the same no matter you access it
     directly or using our tool.

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
    get_created_investigation = investigation.get(entity_id)
    assert get_created_investigation['type'] == 'investigation'
    assert get_created_investigation['schema_version'] == '1.1.3'
    # Send GET request to get type of metric/histogram endpoint
    data_from = get_created_investigation['timestamp']
    metric_histogram = investigation.metric.histogram(params={
        'granularity': 'week', 'from': data_from, 'aggregate-on': 'timestamp'})
    assert metric_histogram['type'] == 'histogram'
    # Send GET request to get type of metric/topn endpoint
    metric_topn = investigation.metric.topn(params={'from': data_from,
                                                 'aggregate-on': 'source'})
    assert metric_topn['type'] == 'topn'
    # Send GET request to get type of metric/cardinality endpoint
    metric_cardinality = investigation.metric.cardinality(params={
        'from': data_from, 'aggregate-on': 'source'})
    assert metric_cardinality['type'] == 'cardinality'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(investigation.search.delete(params={'id': entity_id,
                                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert investigation.search.get(params={'id': entity_id}) == []


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
        7. Create expired judgement via /ctia/judgement/{id}/expire endpoint
        8. Delete entity from the system

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
    # Create expired judgement
    expired_judgement = judgement.expire(entity_id, payload={},
                                         params={'reason': 'For test'})
    assert expired_judgement['reason'] == ' For test'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(judgement.delete(entity_id))
    with pytest.raises(HTTPError):
        judgement.get(entity_id)


def test_python_module_ctia_positive_judgement_search(module_headers,
                                                  module_tool_client):
    """Perform testing for judgement/search entity of custom threat
    intelligence python module

    ID: CCTRI-2848 - 5f5b8907-9e76-4bbb-aa11-330721f569eb

    Steps:

        1. Send POST request to create new judgement entity using custom python
                module
        2. Send GET request using custom python module to read just created
                entity back.
        3. Count entities after entity created
        4. Delete entity from the system
        5. Repeat GET request using python module and validate that entity was
            deleted
        6. Count entities after entity deleted
        7. Compare the amount of entities after creating and deleting entities

    Expectedresults: Actor entity can be created, fetched, counted and
        deleted using custom python module. Data stored in the entity is
        the same no matter you access it directly or using our tool

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
            'type'
        ]
    }
    assert values == payload
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_judgement_search = judgement.search.get(params={'id': entity_id})
    assert get_judgement_search[0]['type'] == 'judgement'
    # Count entities after entity created
    get_judgement_search_count = judgement.search.count()
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(judgement.search.delete(params={'id': entity_id,
                                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert judgement.search.get(params={'id': entity_id}) == []
    # Count entities after entity deleted
    get_judgement_search_count2 = judgement.search.count()
    # Compare results of get_judgement_search_count
    # and get_judgement_search_count2
    assert get_judgement_search_count != get_judgement_search_count2


def test_python_module_ctia_positive_judgement_metric(module_headers,
                                                  module_tool_client):
    """Perform testing for judgement/metric endpoints of custom threat
    intelligence python module

    ID: CCTRI-2848 -7bddcca2-0188-4885-9289-fa0797bf1448

    Steps:

        1. Send POST request to create new judgement entity using custom python
                module
        2. Send GET request using custom python module to read just created
                 entity back.
        3. Send GET request to get type of metric/histogram endpoint
        4. Send GET request to get type of metric/topn endpoint
        5. Send GET request to get type of metric/cardinality endpoint
        6. Delete created entity
        7. Repeat GET request using python module and validate that entity was
            deleted

     Expectedresults: Actor entity can be created, fetched, researched by
         metric's endpoints and deleted using custom python module.
         Data stored in the entity is the same no matter you access it
         directly or using our tool.

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
    get_created_judgement = judgement.get(entity_id)
    assert get_created_judgement['type'] == 'judgement'
    assert get_created_judgement['source'] == 'source'
    # Send GET request to get type of metric/histogram endpoint
    data_from = get_created_judgement['timestamp']
    metric_histogram = judgement.metric.histogram(params={
        'granularity': 'week', 'from': data_from, 'aggregate-on': 'timestamp'})
    assert metric_histogram['type'] == 'histogram'
    # Send GET request to get type of metric/topn endpoint
    metric_topn = judgement.metric.topn(params={'from': data_from,
                                                 'aggregate-on': 'confidence'})
    assert metric_topn['type'] == 'topn'
    # Send GET request to get type of metric/cardinality endpoint
    metric_cardinality = judgement.metric.cardinality(
        params={'from': data_from, 'aggregate-on': 'confidence'})
    assert metric_cardinality['type'] == 'cardinality'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(judgement.search.delete(params={'id': entity_id,
                                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert judgement.search.get(params={'id': entity_id}) == []


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
        'labels': ['malware'],
        'description': 'Test description',
        'title': 'Title for test',
        'short_description': 'Short test description'

    }
    # Create new entity using provided payload
    post_tool_response = malware.post(payload=payload,
                                      params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'title',
            'labels',
            'type',
            'schema_version',
            'description',
            'short_description',

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
            payload={'labels': ['malware'],
                     'description': 'Test description',
                     'title': 'Changed title for test',
                     'short_description': 'Short test description'
                     }
        )
    )
    assert put_tool_response['title'] == 'Changed title for test'
    get_tool_response = malware.get(entity_id)
    assert get_tool_response['title'] == 'Changed title for test'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(malware.delete(entity_id))
    with pytest.raises(HTTPError):
        malware.get(entity_id)


def test_python_module_ctia_positive_malware_search(module_headers,
                                                  module_tool_client):
    """Perform testing for malware/search entity of custom threat
    intelligence python module

    ID: CCTRI-2848 - 9f54a221-0e7b-4410-9737-84c61ab32dfe

    Steps:

        1. Send POST request to create new malware entity using
        custom python module
        2. Send GET request using custom python module to read just created
                entity back.
        3. Count entities after entity created
        4. Delete entity from the system
        5. Repeat GET request using python module and validate that entity was
            deleted
        6. Count entities after entity deleted
        7. Compare the amount of entities after creating and deleting entities

    Expectedresults: malware entity can be created, fetched, counted and
        deleted using custom python module. Data stored in the entity is
        the same no matter you access it directly or using our tool

    Importance: Critical
    """
    malware = module_tool_client.private_intel.malware
    payload = {
        'type': 'malware',
        'schema_version': SERVER_VERSION,
        'labels': ['malware'],
        'description': 'Test description',
        'title': 'Title for test',
        'short_description': 'Short test description'

    }
    # Create new entity using provided payload
    post_tool_response = malware.post(payload=payload,
                                      params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'title',
            'labels',
            'type',
            'schema_version',
            'description',
            'short_description',

        ]
    }
    assert values == payload
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_malware_search = malware.search.get(
        params={'id': entity_id})
    assert get_malware_search[0]['type'] == 'malware'
    assert get_malware_search[0]['schema_version'] == '1.1.3'
    # Count entities after entity created
    get_malware_search_count = malware.search.count()
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(malware.search.delete(params={'id': entity_id,
                                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert malware.search.get(params={'id': entity_id}) == []
    # Count entities after entity deleted
    get_malware_search_count2 = malware.search.count()
    # Compare results of get_malware_search_count
    # and get_malware_search_count2
    assert get_malware_search_count != get_malware_search_count2


def test_python_module_ctia_positive_malware_metric(module_headers,
                                                  module_tool_client):
    """Perform testing for malware/metric endpoints of custom threat
    intelligence python module

    ID: CCTRI-2848 -33b01f79-0d65-4aef-a1b0-c8f497400508

    Steps:

        1. Send POST request to create new malware entity using
        custom python module
        2. Send GET request using custom python module to read just created
                 entity back.
        3. Send GET request to get type of metric/histogram endpoint
        4. Send GET request to get type of metric/topn endpoint
        5. Send GET request to get type of metric/cardinality endpoint
        6. Delete created entity
        7. Repeat GET request using python module and validate that entity was
            deleted

     Expectedresults: malware entity can be created, fetched,
     researched by metric's endpoints and deleted using custom python module.
     Data stored in the entity is the same no matter you access it
     directly or using our tool.

    Importance: Critical
    """
    malware = module_tool_client.private_intel.malware
    payload = {
        'type': 'malware',
        'schema_version': SERVER_VERSION,
        'labels': ['malware'],
        'description': 'Test description',
        'title': 'Title for test',
        'short_description': 'Short test description'

    }
    # Create new entity using provided payload
    post_tool_response = malware.post(payload=payload,
                                      params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'title',
            'labels',
            'type',
            'schema_version',
            'description',
            'short_description',

        ]
    }
    assert values == payload
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_created_malware = malware.get(entity_id)
    assert get_created_malware['type'] == 'malware'
    assert get_created_malware['schema_version'] == '1.1.3'
    # Send GET request to get type of metric/histogram endpoint
    data_from = get_created_malware['timestamp']
    metric_histogram = malware.metric.histogram(params={
        'granularity': 'week', 'from': data_from, 'aggregate-on': 'timestamp'})
    assert metric_histogram['type'] == 'histogram'
    # Send GET request to get type of metric/topn endpoint
    metric_topn = malware.metric.topn(params={'from': data_from,
                                                 'aggregate-on': 'source'})
    assert metric_topn['type'] == 'topn'
    # Send GET request to get type of metric/cardinality endpoint
    metric_cardinality = malware.metric.cardinality(params={
        'from': data_from, 'aggregate-on': 'source'})
    assert metric_cardinality['type'] == 'cardinality'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(malware.search.delete(params={'id': entity_id,
                                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert malware.search.get(params={'id': entity_id}) == []


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
        'schema_version': SERVER_VERSION,
        'description': 'Test description',
        'title': 'Title for test',
        'short_description': 'Short test description'
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


def test_python_module_ctia_positive_relationship_search(module_headers,
                                                  module_tool_client):
    """Perform testing for relationship/search entity of custom threat
    intelligence python module

    ID: CCTRI-2848 - 55dedd52-678a-4513-9b43-0bb88599d3f5

    Steps:

        1. Send POST request to create one campaign entity to be used for
            relationship functionality
        2. Send POST request to create one indicator entity to be used for
            relationship functionality
        3. Send POST request to create new relationship entity using custom
            python module
        4. Send GET request using custom python module to read just created
                entity back.
        5. Count entities after entity created
        6. Delete entity from the system
        7. Repeat GET request using python module and validate that entity was
            deleted
        8. Count entities after entity deleted
        9. Compare the amount of entities after creating and deleting entities

    Expectedresults: relationship entity can be created, fetched, counted and
        deleted using custom python module. Data stored in the entity is
        the same no matter you access it directly or using our tool

    Importance: Critical
    """
    campaign = module_tool_client.private_intel.campaign
    payload = {
        'campaign_type': 'Low',
        'confidence': 'Medium',
        'type': 'campaign',
        'schema_version': SERVER_VERSION,
        'description': 'Test description',
        'title': 'Title for test',
        'short_description': 'Short test description'
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
        'description': 'Test relation',
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
    get_relationship_search = relationship.search.get(
        params={'id': entity_id})
    assert get_relationship_search[0]['type'] == 'relationship'
    assert get_relationship_search[0]['schema_version'] == '1.1.3'
    assert get_relationship_search[0]['description'] == 'Test relation'
    # Count entities after entity created
    get_relationship_search_count = relationship.search.count()
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(relationship.search.delete(params={'id': entity_id,
                                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert relationship.search.get(params={'id': entity_id}) == []
    # Count entities after entity deleted
    get_relationship_search_count2 = relationship.search.count()
    # Compare results of get_relationship_search_count
    # and get_relationship_search_count2
    assert get_relationship_search_count != get_relationship_search_count2


def test_python_module_ctia_positive_relationship_metric(module_headers,
                                                  module_tool_client):
    """Perform testing for relationship/metric endpoints of custom threat
    intelligence python module

    ID: CCTRI-2848 -4d34bfc9-eec7-4c28-b53c-f6c83e46a9d1

    Steps:

        1. Send POST request to create one campaign entity to be used for
            relationship functionality
        2. Send POST request to create one indicator entity to be used for
            relationship functionality
        3. Send POST request to create new relationship entity using custom
            python module
        4. Send GET request using custom python module to read just created
                 entity back.
        5. Send GET request to get type of metric/histogram endpoint
        6. Send GET request to get type of metric/topn endpoint
        7. Send GET request to get type of metric/cardinality endpoint
        8. Delete created entity
        9. Repeat GET request using python module and validate that entity was
            deleted

     Expectedresults: relationship entity can be created, fetched,
     researched by metric's endpoints and deleted using custom python module.
     Data stored in the entity is the same no matter you access it
     directly or using our tool.

    Importance: Critical
    """
    campaign = module_tool_client.private_intel.campaign
    payload = {
        'campaign_type': 'Low',
        'confidence': 'Medium',
        'type': 'campaign',
        'schema_version': SERVER_VERSION,
        'description': 'Test description',
        'title': 'Title for test',
        'short_description': 'Short test description'
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
        'description': 'Test relation',
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
    get_created_relationship = relationship.get(entity_id)
    assert get_created_relationship['type'] == 'relationship'
    assert get_created_relationship['schema_version'] == '1.1.3'
    assert get_created_relationship['description'] == 'Test relation'
    # Send GET request to get type of metric/histogram endpoint
    data_from = get_created_relationship['timestamp']
    metric_histogram = relationship.metric.histogram(params={
        'granularity': 'week', 'from': data_from, 'aggregate-on': 'timestamp'})
    assert metric_histogram['type'] == 'histogram'
    # Send GET request to get type of metric/topn endpoint
    metric_topn = relationship.metric.topn(params={'from': data_from,
                                                 'aggregate-on': 'source'})
    assert metric_topn['type'] == 'topn'
    # Send GET request to get type of metric/cardinality endpoint
    metric_cardinality = relationship.metric.cardinality(params={
        'from': data_from, 'aggregate-on': 'source'})
    assert metric_cardinality['type'] == 'cardinality'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(relationship.search.delete(params={'id': entity_id,
                                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert relationship.search.get(params={'id': entity_id}) == []


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


def test_python_module_ctia_positive_sighting_search(module_headers,
                                                  module_tool_client):
    """Perform testing for sighting/search entity of custom threat
    intelligence python module

    ID: CCTRI-2848 - cbe1ae9b-8889-45d0-ac14-a4ec71c7208a

    Steps:

        1. Send POST request to create new sighting entity using
        custom python module
        2. Send GET request using custom python module to read just created
                entity back.
        3. Count entities after entity created
        4. Delete entity from the system
        5. Repeat GET request using python module and validate that entity was
            deleted
        6. Count entities after entity deleted
        7. Compare the amount of entities after creating and deleting entities

    Expectedresults: sighting entity can be created, fetched, counted and
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
    post_sighting_response = sighting.post(payload=payload,
                                       params={'wait_for': 'true'})
    values = {
        key: post_sighting_response[key] for key in [
            'count',
            'observed_time',
            'confidence',
            'type',
            'schema_version'
        ]
    }
    assert values == payload
    entity_id = post_sighting_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_sighting_search = sighting.search.get(
        params={'id': entity_id})
    assert get_sighting_search[0]['type'] == 'sighting'
    assert get_sighting_search[0]['schema_version'] == '1.1.3'
    # Count entities after entity created
    get_sighting_search_count = sighting.search.count()
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(sighting.search.delete(params={'id': entity_id,
                                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert sighting.search.get(params={'id': entity_id}) == []
    # Count entities after entity deleted
    get_sighting_search_count2 = sighting.search.count()
    # Compare results of get_sighting_search_count
    # and get_sighting_search_count2
    assert get_sighting_search_count != get_sighting_search_count2


def test_python_module_ctia_positive_sighting_metric(module_headers,
                                                  module_tool_client):
    """Perform testing for sighting/metric endpoints of custom threat
    intelligence python module

    ID: CCTRI-2848 -edbab647-5ba8-4756-be13-4ebe96d4c899

    Steps:

        1. Send POST request to create new sighting entity using
        custom python module
        2. Send GET request using custom python module to read just created
                 entity back.
        3. Send GET request to get type of metric/histogram endpoint
        4. Send GET request to get type of metric/topn endpoint
        5. Send GET request to get type of metric/cardinality endpoint
        6. Delete created entity
        7. Repeat GET request using python module and validate that entity was
            deleted

     Expectedresults: sighting entity can be created, fetched,
     researched by metric's endpoints and deleted using custom python module.
     Data stored in the entity is the same no matter you access it
     directly or using our tool.

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
    post_sighting_response = sighting.post(payload=payload,
                                           params={'wait_for': 'true'})
    values = {
        key: post_sighting_response[key] for key in [
            'count',
            'observed_time',
            'confidence',
            'type',
            'schema_version'
        ]
    }
    assert values == payload
    entity_id = post_sighting_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_created_sighting = sighting.get(entity_id)
    assert get_created_sighting['type'] == 'sighting'
    assert get_created_sighting['schema_version'] == '1.1.3'
    # Send GET request to get type of metric/histogram endpoint
    data_from = get_created_sighting['timestamp']
    metric_histogram = sighting.metric.histogram(params={
        'granularity': 'week', 'from': data_from, 'aggregate-on': 'timestamp'})
    assert metric_histogram['type'] == 'histogram'
    # Send GET request to get type of metric/topn endpoint
    metric_topn = sighting.metric.topn(params={'from': data_from,
                                                 'aggregate-on': 'source'})
    assert metric_topn['type'] == 'topn'
    # Send GET request to get type of metric/cardinality endpoint
    metric_cardinality = sighting.metric.cardinality(params={
        'from': data_from, 'aggregate-on': 'source'})
    assert metric_cardinality['type'] == 'cardinality'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(sighting.search.delete(params={'id': entity_id,
                                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert sighting.search.get(params={'id': entity_id}) == []


def test_python_module_ctia_positive_target_record(
        module_headers, module_tool_client):
    """Perform testing for target_record entity of custom threat intelligence
     python module

    ID: CCTRI-2906 - 3392e79b-b8c7-4ff8-b261-a1032bc78cbd

    Steps:

        1. Send POST request to create new target_record entity using custom
         python module
        2. Send GET request using custom python module to read just created
            entity back.
        3. Send same GET request, but using direct access to the server
        4. Compare results
        5. Validate that GET request of external_id returns number of
        external_id
        6. Update target_record entity using custom python module
        7. Repeat GET request using python module and validate that entity was
            updated
        8. Delete entity from the system

    Expectedresults: Sighting entity can be created, fetched, updated and
        deleted using custom python module. Data stored in the entity is
        the same no matter you access it directly or using our tool

    Importance: Critical
    """
    target_record = module_tool_client.private_intel.target_record
    payload = {
        "targets": [
            {
            "type": "string",
            "observables": [
            {
                    "value": "asdf.com",
                    "type": "domain"
            }
            ],
            "observed_time": {
                    "start_time": "2021-08-05T14:17:54.726Z",
                    "end_time": "2021-08-05T14:17:54.726Z"
            }
            }
            ],
        'source': 'For test',
        'type': 'target-record',
        'schema_version': SERVER_VERSION,
        'external_ids': ['3']
    }
    # Create new entity using provided payload
    post_tool_response = target_record.post(payload=payload,
                                       params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'source',
            'targets',
            'type',
            'schema_version',
            'external_ids'
        ]
    }
    assert values == payload
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_tool_response = target_record.get(entity_id)
    get_direct_response = ctia_get_data(
        target_url=TARGET_RECORD,
        entity_id=entity_id,
        **{'headers': module_headers}
    ).json()
    assert get_tool_response == get_direct_response
    # Validate that GET request of external_id returns appropriate value
    external_id_result = target_record.external_id(3)
    assert external_id_result[0]['external_ids'] == ['3']
    # Update entity values
    put_tool_response = delayed_return(
        target_record.put(
            id_=entity_id,
            payload={
                'source': 'Updated source',
                'targets': [
                    {
                        "type": "string",
                        "observables": [
                            {
                                "value": "asdf.com",
                                "type": "domain"
                            }
                            ],
                        "observed_time": {
                            "start_time": "2021-08-05T14:17:54.726Z",
                            "end_time": "2021-08-05T14:17:54.726Z"
                        }
                    }
                ]
                }
        )
    )
    assert put_tool_response['source'] == 'Updated source'
    get_tool_response = target_record.get(entity_id)
    assert get_tool_response['source'] == 'Updated source'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(target_record.delete(entity_id))
    with pytest.raises(HTTPError):
        target_record.get(entity_id)


def test_python_module_ctia_positive_target_record_search(module_headers,
                                                  module_tool_client):
    """Perform testing for target_record/search entity of custom threat
    intelligence python module

    ID: CCTRI-2906 - b1fd55c7-cbae-43c7-a246-725948563e96

    Steps:

        1. Send POST request to create new target_record entity using
        custom python module
        2. Send GET request using custom python module to read just created
                entity back.
        3. Count entities after entity created
        4. Delete entity from the system
        5. Repeat GET request using python module and validate that entity was
            deleted
        6. Count entities after entity deleted
        7. Compare the amount of entities after creating and deleting entities

    Expectedresults: target_record entity can be created, fetched, counted and
        deleted using custom python module. Data stored in the entity is
        the same no matter you access it directly or using our tool

    Importance: Critical
    """
    target_record = module_tool_client.private_intel.target_record
    payload = {
        "targets": [
            {
                "type": "string",
                "observables": [
                    {
                        "value": "asdf.com",
                        "type": "domain"
                    }
                ],
                "observed_time": {
                    "start_time": "2021-08-05T14:17:54.726Z",
                    "end_time": "2021-08-05T14:17:54.726Z"
                }
            }
        ],
        'source': 'For test',
        'type': 'target-record',
        'schema_version': SERVER_VERSION
    }
    # Create new entity using provided payload
    post_tool_response = target_record.post(payload=payload,
                                            params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'source',
            'targets',
            'type',
            'schema_version'
        ]
    }
    assert values == payload
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_target_record_search = target_record.search.get(
        params={'id': entity_id})
    assert get_target_record_search[0]['type'] == 'target-record'
    assert get_target_record_search[0]['schema_version'] == '1.1.3'
    # Count entities after entity created
    get_target_record_search_count = target_record.search.count()
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(target_record.search.delete(params={'id': entity_id,
                                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert target_record.search.get(params={'id': entity_id}) == []
    # Count entities after entity deleted
    get_target_record_search_count2 = target_record.search.count()
    # Compare results of get_target_record_search_count
    # and get_target_record_search_count2
    assert get_target_record_search_count != get_target_record_search_count2


def test_python_module_ctia_positive_target_record_metric(module_headers,
                                                  module_tool_client):
    """Perform testing for target_record/metric endpoints of custom threat
    intelligence python module

    ID: CCTRI-2906 -e3426742-294f-406a-9fb0-06958c369c3d

    Steps:

        1. Send POST request to create new target_record entity using
        custom python module
        2. Send GET request using custom python module to read just created
                 entity back.
        3. Send GET request to get type of metric/histogram endpoint
        4. Send GET request to get type of metric/topn endpoint
        5. Send GET request to get type of metric/cardinality endpoint
        6. Delete created entity
        7. Repeat GET request using python module and validate that entity was
            deleted

     Expectedresults: target_record entity can be created, fetched,
     researched by metric's endpoints and deleted using custom python module.
     Data stored in the entity is the same no matter you access it
     directly or using our tool.

    Importance: Critical
    """
    target_record = module_tool_client.private_intel.target_record
    payload = {
        "targets": [
            {
                "type": "string",
                "observables": [
                    {
                        "value": "asdf.com",
                        "type": "domain"
                    }
                ],
                "observed_time": {
                    "start_time": "2021-08-05T14:17:54.726Z",
                    "end_time": "2021-08-05T14:17:54.726Z"
                }
            }
        ],
        'source': 'For test',
        'type': 'target-record',
        'schema_version': SERVER_VERSION
    }
    # Create new entity using provided payload
    post_tool_response = target_record.post(payload=payload,
                                            params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'source',
            'targets',
            'type',
            'schema_version'
        ]
    }
    assert values == payload
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_created_target_record = target_record.get(entity_id)
    assert get_created_target_record['type'] == 'target-record'
    assert get_created_target_record['schema_version'] == '1.1.3'
    # Send GET request to get type of metric/histogram endpoint
    data_from = get_created_target_record['timestamp']
    metric_histogram = target_record.metric.histogram(params={
        'granularity': 'week', 'from': data_from, 'aggregate-on': 'timestamp'})
    assert metric_histogram['type'] == 'histogram'
    # Send GET request to get type of metric/topn endpoint
    metric_topn = target_record.metric.topn(params={'from': data_from,
                                                 'aggregate-on': 'source'})
    assert metric_topn['type'] == 'topn'
    # Send GET request to get type of metric/cardinality endpoint
    metric_cardinality = target_record.metric.cardinality(params={
        'from': data_from, 'aggregate-on': 'source'})
    assert metric_cardinality['type'] == 'cardinality'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(target_record.search.delete(params={'id': entity_id,
                                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert target_record.search.get(params={'id': entity_id}) == []


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
        'labels': ['tool'],
        'type': 'tool',
        'schema_version': SERVER_VERSION,
        'description': 'Test description',
        'title': 'Title for test',
        'short_description': 'Short test description'
    }
    # Create new entity using provided payload
    post_tool_response = tool.post(payload=payload,
                                   params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'labels',
            'type',
            'schema_version',
            'description',
            'title',
            'short_description'
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
            payload={'labels': ['tool'],
                     'description': 'Test description',
                     'title': 'Changed title for test',
                     'short_description': 'Short test description'
                     }
        )
    )
    assert put_tool_response['title'] == 'Changed title for test'
    get_tool_response = tool.get(entity_id)
    assert get_tool_response['title'] == 'Changed title for test'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(tool.delete(entity_id))
    with pytest.raises(HTTPError):
        tool.get(entity_id)
    # Validate CCTRI-1036 defect
    with pytest.raises(HTTPError):
        tool.delete(entity_id)


def test_python_module_ctia_positive_tool_search(module_headers,
                                                  module_tool_client):
    """Perform testing for tool/search entity of custom threat
    intelligence python module

    ID: CCTRI-2848 - cbe1ae9b-8889-45d0-ac14-a4ec71c7208a

    Steps:

        1. Send POST request to create new tool entity using
        custom python module
        2. Send GET request using custom python module to read just created
                entity back.
        3. Count entities after entity created
        4. Delete entity from the system
        5. Repeat GET request using python module and validate that entity was
            deleted
        6. Count entities after entity deleted
        7. Compare the amount of entities after creating and deleting entities

    Expectedresults: tool entity can be created, fetched, counted and
        deleted using custom python module. Data stored in the entity is
        the same no matter you access it directly or using our tool

    Importance: Critical
    """
    tool = module_tool_client.private_intel.tool
    payload = {
        'labels': ['tool'],
        'type': 'tool',
        'schema_version': SERVER_VERSION,
        'description': 'Test description',
        'title': 'Title for test',
        'short_description': 'Short test description'
    }
    # Create new entity using provided payload
    post_tool_response = tool.post(payload=payload,
                                   params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'labels',
            'type',
            'schema_version',
            'description',
            'title',
            'short_description'
        ]
    }
    assert values == payload
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_tool_search = tool.search.get(
        params={'id': entity_id})
    assert get_tool_search[0]['type'] == 'tool'
    assert get_tool_search[0]['schema_version'] == '1.1.3'
    # Count entities after entity created
    get_tool_search_count = tool.search.count()
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(tool.search.delete(params={'id': entity_id,
                                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert tool.search.get(params={'id': entity_id}) == []
    # Count entities after entity deleted
    get_tool_search_count2 = tool.search.count()
    # Compare results of get_tool_search_count
    # and get_tool_search_count2
    assert get_tool_search_count != get_tool_search_count2


def test_python_module_ctia_positive_tool_metric(module_headers,
                                                  module_tool_client):
    """Perform testing for tool/metric endpoints of custom threat
    intelligence python module

    ID: CCTRI-2848 -edbab647-5ba8-4756-be13-4ebe96d4c899

    Steps:

        1. Send POST request to create new tool entity using
        custom python module
        2. Send GET request using custom python module to read just created
                 entity back.
        3. Send GET request to get type of metric/histogram endpoint
        4. Send GET request to get type of metric/topn endpoint
        5. Send GET request to get type of metric/cardinality endpoint
        6. Delete created entity
        7. Repeat GET request using python module and validate that entity was
            deleted

     Expectedresults: tool entity can be created, fetched,
     researched by metric's endpoints and deleted using custom python module.
     Data stored in the entity is the same no matter you access it
     directly or using our tool.

    Importance: Critical
    """
    tool = module_tool_client.private_intel.tool
    payload = {
        'labels': ['tool'],
        'type': 'tool',
        'schema_version': SERVER_VERSION,
        'description': 'Test description',
        'title': 'Title for test',
        'short_description': 'Short test description'
    }
    # Create new entity using provided payload
    post_tool_response = tool.post(payload=payload,
                                   params={'wait_for': 'true'})
    values = {
        key: post_tool_response[key] for key in [
            'labels',
            'type',
            'schema_version',
            'description',
            'title',
            'short_description'
        ]
    }
    assert values == payload
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_created_tool = tool.get(entity_id)
    assert get_created_tool['type'] == 'tool'
    assert get_created_tool['schema_version'] == '1.1.3'
    # Send GET request to get type of metric/histogram endpoint
    data_from = get_created_tool['timestamp']
    metric_histogram = tool.metric.histogram(params={
        'granularity': 'week', 'from': data_from, 'aggregate-on': 'timestamp'})
    assert metric_histogram['type'] == 'histogram'
    # Send GET request to get type of metric/topn endpoint
    metric_topn = tool.metric.topn(params={'from': data_from,
                                                 'aggregate-on': 'source'})
    assert metric_topn['type'] == 'topn'
    # Send GET request to get type of metric/cardinality endpoint
    metric_cardinality = tool.metric.cardinality(params={
        'from': data_from, 'aggregate-on': 'source'})
    assert metric_cardinality['type'] == 'cardinality'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(tool.search.delete(params={'id': entity_id,
                                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert tool.search.get(params={'id': entity_id}) == []


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


def test_python_module_ctia_positive_vulnerability_search(module_headers,
                                                  module_tool_client):
    """Perform testing for vulnerability/search entity of custom threat
    intelligence python module

    ID: CCTRI-2848 - 642bcca5-3eec-4955-b395-e4c365b65bf5

    Steps:

        1. Send POST request to create new vulnerability entity using
        custom python module
        2. Send GET request using custom python module to read just created
                entity back.
        3. Count entities after entity created
        4. Delete entity from the system
        5. Repeat GET request using python module and validate that entity was
            deleted
        6. Count entities after entity deleted
        7. Compare the amount of entities after creating and deleting entities

    Expectedresults: vulnerability entity can be created, fetched, counted and
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
    get_vulnerability_search = vulnerability.search.get(
        params={'id': entity_id})
    assert get_vulnerability_search[0]['type'] == 'vulnerability'
    assert get_vulnerability_search[0]['schema_version'] == '1.1.3'
    # Count entities after entity created
    get_vulnerability_search_count = vulnerability.search.count()
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(vulnerability.search.delete(params={'id': entity_id,
                                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert vulnerability.search.get(params={'id': entity_id}) == []
    # Count entities after entity deleted
    get_vulnerability_search_count2 = vulnerability.search.count()
    # Compare results of get_vulnerability_search_count
    # and get_vulnerability_search_count2
    assert get_vulnerability_search_count != get_vulnerability_search_count2


def test_python_module_ctia_positive_vulnerability_metric(module_headers,
                                                  module_tool_client):
    """Perform testing for vulnerability/metric endpoints of custom threat
    intelligence python module

    ID: CCTRI-2848 -1b6c327c-cf55-4e22-a72c-93f9ad4b2763

    Steps:

        1. Send POST request to create new vulnerability entity using
        custom python module
        2. Send GET request using custom python module to read just created
                 entity back.
        3. Send GET request to get type of metric/histogram endpoint
        4. Send GET request to get type of metric/topn endpoint
        5. Send GET request to get type of metric/cardinality endpoint
        6. Delete created entity
        7. Repeat GET request using python module and validate that entity was
            deleted

     Expectedresults: vulnerability entity can be created, fetched,
     researched by metric's endpoints and deleted using custom python module.
     Data stored in the entity is the same no matter you access it
     directly or using our tool.

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
    get_created_vulnerability = vulnerability.get(entity_id)
    assert get_created_vulnerability['type'] == 'vulnerability'
    assert get_created_vulnerability['schema_version'] == '1.1.3'
    # Send GET request to get type of metric/histogram endpoint
    data_from = get_created_vulnerability['timestamp']
    metric_histogram = vulnerability.metric.histogram(params={
        'granularity': 'week', 'from': data_from, 'aggregate-on': 'timestamp'})
    assert metric_histogram['type'] == 'histogram'
    # Send GET request to get type of metric/topn endpoint
    metric_topn = vulnerability.metric.topn(params={'from': data_from,
                                                 'aggregate-on': 'source'})
    assert metric_topn['type'] == 'topn'
    # Send GET request to get type of metric/cardinality endpoint
    metric_cardinality = vulnerability.metric.cardinality(params={
        'from': data_from, 'aggregate-on': 'source'})
    assert metric_cardinality['type'] == 'cardinality'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(vulnerability.search.delete(params={'id': entity_id,
                                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert vulnerability.search.get(params={'id': entity_id}) == []


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


def test_python_module_ctia_positive_weakness_search(module_headers,
                                                  module_tool_client):
    """Perform testing for weakness/search entity of custom threat
    intelligence python module

    ID: CCTRI-2848 - a01b4f84-9661-4b67-ac94-cc5ce4ec3cb9

    Steps:

        1. Send POST request to create new weakness entity using custom python
                module
        2. Send GET request using custom python module to read just created
                entity back.
        3. Count entities after entity created
        4. Delete entity from the system
        5. Repeat GET request using python module and validate that entity was
            deleted
        6. Count entities after entity deleted
        7. Compare the amount of entities after creating and deleting entities

    Expectedresults: weakness entity can be created, fetched, counted and
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
    # Create variable for using it in params for endpoints
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_weakness_search = weakness.search.get(params={'id': entity_id})
    assert get_weakness_search[0]['type'] == 'weakness'
    assert get_weakness_search[0]['schema_version'] == '1.1.3'
    # Count entities after entity created
    get_weakness_search_count = weakness.search.count()
    # Delete the entity and make atcctempt to get it back to validate it is
    # not there anymore
    delayed_return(weakness.search.delete(params={'id': entity_id,
                                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert weakness.search.get(params={'id': entity_id}) == []
    # Count entities after entity deleted
    get_weakness_search_count2 = weakness.search.count()
    # Compare results of get_weakness_search_count
    # and get_weakness_search_count2
    assert get_weakness_search_count != get_weakness_search_count2


def test_python_module_ctia_positive_weakness_metric(module_headers,
                                                  module_tool_client):
    """Perform testing for weakness/metric endpoints of custom threat
    intelligence python module

    ID: CCTRI-2848 -52c89f1b-9728-41d6-8a1f-07dd0ec8b976

    Steps:

        1. Send POST request to create new weakness entity using custom python
                module
        2. Send GET request using custom python module to read just created
                 entity back.
        3. Send GET request to get type of metric/histogram endpoint
        4. Send GET request to get type of metric/topn endpoint
        5. Send GET request to get type of metric/cardinality endpoint
        6. Delete created entity
        7. Repeat GET request using python module and validate that entity was
            deleted

     Expectedresults: weakness entity can be created, fetched, researched by
         metric's endpoints and deleted using custom python module.
         Data stored in the entity is the same no matter you access it
         directly or using our tool.

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
    # Create variable for using it in params for endpoints
    entity_id = post_tool_response['id'].rpartition('/')[-1]
    # Validate that GET request return same data for direct access and access
    # through custom python module
    get_created_weakness = weakness.get(entity_id)
    assert get_created_weakness['type'] == 'weakness'
    assert get_created_weakness['likelihood'] == 'Medium'
    assert get_created_weakness['schema_version'] == '1.1.3'
    # Send GET request to get type of metric/histogram endpoint
    data_from = get_created_weakness['timestamp']
    metric_histogram = weakness.metric.histogram(params={'granularity': 'week',
                                                      'from': data_from,
                                                'aggregate-on': 'timestamp'})
    assert metric_histogram['type'] == 'histogram'
    # Send GET request to get type of metric/topn endpoint
    metric_topn = weakness.metric.topn(params={'from': data_from,
                                                 'aggregate-on': 'source'})
    assert metric_topn['type'] == 'topn'
    # Send GET request to get type of metric/cardinality endpoint
    metric_cardinality = weakness.metric.cardinality(params={'from': data_from,
                                            'aggregate-on': 'source'})
    assert metric_cardinality['type'] == 'cardinality'
    # Delete the entity and make attempt to get it back to validate it is
    # not there anymore
    delayed_return(weakness.search.delete(params={'id': entity_id,
                                'REALLY_DELETE_ALL_THESE_ENTITIES': 'true'}))
    # Repeat GET request and validate that entity was deleted
    assert weakness.search.get(params={'id': entity_id}) == []
