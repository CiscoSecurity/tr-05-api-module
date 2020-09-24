from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.int import (
    int_get_integration,
    int_get_integration_by_id,
    int_post_integration,
    int_patch_integration,
    int_delete_integration,
    int_get_module_instance,
    int_get_module_instance_by_id,
    int_post_module_instance,
    int_patch_module_instance,
    int_delete_module_instance,
    int_get_module_type,
    int_get_module_type_by_id,
    int_post_module_type,
    int_patch_module_type,
    int_delete_module_type,
)


CUSTOM_RELAY_MODULE_TYPE = 'a14ae422-01b6-5013-9876-695ff1b0ebe0'
PRIVATE_INTEL_MODULE_TYPE = '2c8b4134-c521-5be5-aaf8-af06e5e27cbb'
SHA256_HASH = (
    '10745318f9dd601ab76f029cbc41c7e13c9754f87eb2c85948734b2b0b148140')


def test_ctr_positive_end_to_end_integration(module_headers):
    """Perform testing for int integration end point

    ID: ed5700a9-d020-4c9e-bb3a-adc5e91f7508

    Steps:

        1. Send POST request to int integration end point to create new entity
        2. Send GET request to fetch all integration entities and check that
            one we created is present here
        3. Send GET request to get specific entity and validate that all fields
            contain expected data
        4. Send PATCH request to update entity with specific data
        5. Send DELETE request to delete entity

    Expectedresults: End to end scenario for int integration end point works
        properly

    Importance: High
    """
    # Validate that integration we plan to use for test automation purpose is
    # not present in system
    integration_list = int_get_integration(**{'headers': module_headers})
    assert len(integration_list) > 0, (
        'There are no integrations in selected sandbox'
    )
    integration = next(
        (
            item for item in integration_list
            if item['title'] == 'Test Automation Integration Demo'
        ),
        False
    )
    assert not integration, (
        'Test integration was not removed from the system from previous runs'
    )
    # Create new integration
    payload = {
        'description': 'Test Automation Integration Demo',
        'tips': 'Some useful tips',
        'module_type_id': CUSTOM_RELAY_MODULE_TYPE,
        'org_id': 'system',
        'short_description': 'Demo Integration',
        'title': 'Test Automation Integration Demo',
        'user_id': 'system',
        'client_id': 'system',
        'flags': ['default'],
        'enabled': True,
    }
    response = int_post_integration(
        payload=payload, **{'headers': module_headers})
    assert response['title'] == 'Test Automation Integration Demo'
    # Check that new integration was created
    integration_list = int_get_integration(**{'headers': module_headers})
    integration = next(
        (
            item for item in integration_list
            if item['title'] == 'Test Automation Integration Demo'
        ),
        False
    )
    assert integration, 'Test integration cannot be found'
    # Check that integration contains valid data
    integration = int_get_integration_by_id(
        response['id'], **{'headers': module_headers})
    for key in [
        'description',
        'title',
        'module_type_id',
        'flags',
        'enabled',
        'tips',
        'short_description'
    ]:
        assert integration[key] == payload[key]
    assert integration['user_id']
    assert integration['org_id']
    assert 'client-' in integration['client_id']
    assert integration['visibility'] == 'org'
    assert integration['created_at']
    # Update integration with new data
    patch_payload = {
        'tips': 'New tips', 'flags': ['beta']}
    response = int_patch_integration(
        payload=patch_payload,
        entity_id=integration['id'],
        **{'headers': module_headers}
    )
    assert response['tips'] == 'New tips'
    assert response['flags'] == ['beta']
    # Check that entity was updated properly
    integration = int_get_integration_by_id(
        integration['id'], **{'headers': module_headers})
    assert integration['tips'] == 'New tips'
    assert integration['flags'] == ['beta']
    # Delete integration
    response = int_delete_integration(
        entity_id=integration['id'], **{'headers': module_headers})
    assert response.status_code == 204
    response = int_get_integration_by_id(
        integration['id'], **{'headers': module_headers})
    assert response['error'] == 'integration_not_found'


def test_ctr_positive_end_to_end_module_type(module_headers):
    """Perform testing for int module type end point

    ID: 4b423a70-aae4-42fe-9d31-b106b5ab629d

    Steps:

        1. Send POST request to int module type end point to create new entity
        2. Send GET request to fetch all module type entities and check that
            one we created is present here
        3. Send GET request to get specific entity and validate that all fields
            contain expected data
        4. Send PATCH request to update entity with specific data
        5. Send DELETE request to delete entity

    Expectedresults: End to end scenario for int module type end point works
        properly

    Importance: High
    """
    # Validate that module type we plan to use for test automation purpose is
    # not present in system
    module_type_list = int_get_module_type(**{'headers': module_headers})
    assert len(module_type_list) > 0, (
        'There are no module types in selected sandbox'
    )
    module_type = next(
        (
            item for item in module_type_list
            if item['default_name'] == 'Test Automation Module Type Demo'
        ),
        False
    )
    assert not module_type, (
        'Test module type was not removed from the system from previous runs'
    )
    # Create new module type
    payload = {
        'description': 'Test Automation Module Type Demo',
        'capabilities': [
            {'id': 'health', 'description': 'Healthcheck'},
            {'id': 'deliberate', 'description': 'Deliberation'},
            {'id': 'observe', 'description': 'Enrichments'},
            {'id': 'refer', 'description': 'Reference links'},
            {'id': 'respond', 'description': 'Response actions'},
            {'id': 'tiles', 'description': 'Dashboard tiles'}
        ],
        'tips': 'Some useful tips',
        'title': 'Test Automation Module Type Demo',
        'default_name': 'Test Automation Module Type Demo',
        'flags': ['default'],
        'short_description': 'Demo Module Type',
        'enabled': True,
    }
    response = int_post_module_type(
        payload=payload, **{'headers': module_headers})
    assert response['default_name'] == 'Test Automation Module Type Demo'
    # Check that new module type was created
    module_type_list = int_get_module_type(**{'headers': module_headers})
    module_type = next(
        (
            item for item in module_type_list
            if item['default_name'] == 'Test Automation Module Type Demo'
        ),
        False
    )
    assert module_type, 'Test module type cannot be found'
    # Check that module type contains valid data
    module_type = int_get_module_type_by_id(
        response['id'], **{'headers': module_headers})
    for key in [
        'description',
        'capabilities',
        'tips',
        'title',
        'default_name',
        'flags',
        'enabled',
        'short_description'
    ]:
        assert module_type[key] == payload[key]
    assert module_type['user_id']
    assert module_type['org_id']
    assert module_type['client_id']
    assert module_type['record'] == 'relay-module.module/RelayModule'
    assert module_type['visibility'] == 'org'
    assert module_type['created_at']
    # Update module type with new data
    patch_payload = {
        'description': 'New demo', 'flags': ['beta']}
    response = int_patch_module_type(
        payload=patch_payload,
        entity_id=module_type['id'],
        **{'headers': module_headers}
    )
    assert response['description'] == 'New demo'
    assert response['flags'] == ['beta']
    # Check that entity was updated properly
    module_type = int_get_module_type_by_id(
        module_type['id'], **{'headers': module_headers})
    assert module_type['description'] == 'New demo'
    assert module_type['flags'] == ['beta']
    # Delete module type
    response = int_delete_module_type(
        entity_id=module_type['id'], **{'headers': module_headers})
    assert response.status_code == 204
    response = int_get_module_type_by_id(
        module_type['id'], **{'headers': module_headers})
    assert response['error'] == 'module_type_not_found'


def test_ctr_positive_end_to_end_module_instance(module_headers):
    """Perform testing for int module instance end point

    ID: a814f45b-5ed5-49e5-85a0-b1c310333751

    Steps:

        1. Send POST request to int module instance end point to create new
            entity
        2. Send GET request to fetch all module instance entities and check
            that one we created is present here
        3. Send GET request to get specific entity and validate that all fields
            contain expected data
        4. Send PATCH request to update entity with specific data
        5. Send DELETE request to delete entity

    Expectedresults: End to end scenario for int module instance end point
        works properly

    Importance: High
    """
    # Validate that module instance we plan to use for test automation purpose
    # is not present in system
    module_instance_list = int_get_module_instance(
        **{'headers': module_headers})
    assert len(module_instance_list) > 0, (
        'There are no module types in selected sandbox'
    )
    module_instance = next(
        (
            item for item in module_instance_list
            if item['name'] == 'Test Automation Module'
        ),
        False
    )
    assert not module_instance, (
        'Test module instance was not removed from the system from previous '
        'runs'
    )
    # Create new module instance
    payload = {
        'name': 'Test Automation Module',
        'module_type_id': CUSTOM_RELAY_MODULE_TYPE,
        'enabled': True,
        'visibility': 'org',
        'settings': {
            'url': 'https://unayyja4q2.execute-api.eu-central-1.amazonaws.com/'
                   'dev',
            'supported-apis': [
                'health',
                'observe/observables',
                'deliberate/observables',
                'refer/observables',
                'respond/observables',
                'respond/trigger'
            ]
        }
    }
    response = int_post_module_instance(
        payload=payload, **{'headers': module_headers})
    assert response['name'] == 'Test Automation Module'
    # Check that new module instance was created
    module_instance_list = int_get_module_instance(
        **{'headers': module_headers})
    module_instance = next(
        (
            item for item in module_instance_list
            if item['name'] == 'Test Automation Module'
        ),
        False
    )
    assert module_instance, 'Test module instance cannot be found'
    # Check that module instance contains valid data
    module_instance = int_get_module_instance_by_id(
        response['id'], **{'headers': module_headers})
    for key in [
        'name',
        'module_type_id',
        'visibility',
        'settings',
    ]:
        assert module_instance[key] == payload[key]
    assert module_instance['user_id']
    assert module_instance['org_id']
    assert module_instance['client_id']
    assert module_instance['client_id']
    assert module_instance['created_at']
    # Update module instance with new data
    patch_payload = {'name': 'Updated Test Automation Module'}
    response = int_patch_module_instance(
        payload=patch_payload,
        entity_id=module_instance['id'],
        **{'headers': module_headers}
    )
    assert response['name'] == 'Updated Test Automation Module'
    # Check that entity was updated properly
    module_instance = int_get_module_instance_by_id(
        module_instance['id'], **{'headers': module_headers})
    assert module_instance['name'] == 'Updated Test Automation Module'
    # Delete module instance
    response = int_delete_module_instance(
        entity_id=module_instance['id'], **{'headers': module_headers})
    assert response.status_code == 204
    response = int_get_module_instance_by_id(
        module_instance['id'], **{'headers': module_headers})
    assert response['error'] == 'module_instance_not_found'


def test_ctr_positive_module_instance_investigate(
        module_headers, module_tool_client):
    """Validate that module we create through int module instance end point
    can return data for observable investigation process

    ID: 15b9b1c0-b771-42a7-b6a6-861682a09d17

    Steps:

        1. Send POST request to int module instance end point to create new
            entity
        2. Send enrich observe observable request to server
        3. Check response for data from just created custom module

    Expectedresults: Data returned from server contains valid and expected
        values

    Importance: High
    """
    # Validate that module instance we plan to use for test automation purpose
    # is not present in system
    module_instance_list = int_get_module_instance(
        **{'headers': module_headers})
    module_instance = next(
        (
            item for item in module_instance_list
            if item['name'] == 'Test Investigation Module'
        ),
        False
    )
    assert not module_instance, (
        'Test module instance was not removed from the system from previous '
        'runs'
    )
    # Create new module instance
    payload = {
        'name': 'Investigation Module',
        'module_type_id': PRIVATE_INTEL_MODULE_TYPE,
        'enabled': True,
        'visibility': 'org',
    }
    module_instance = int_post_module_instance(
        payload=payload, **{'headers': module_headers})
    assert module_instance['name'] == 'Investigation Module'

    try:
        # Check that created module can return data for investigation process
        response = module_tool_client.enrich.observe.observables(
            [{'type': 'sha256', 'value': SHA256_HASH}])['data']
        observables = get_observables(response, module_instance['name'])
        assert observables['data']['verdicts']['count'] > 0, (
            'No observable verdicts returned from server. Check hash value')
        assert observables['data']['judgements']['count'] > 0, (
            'No observable judgements returned from server. Check hash value')
        assert observables['data']['verdicts']['docs'][0][
            'disposition_name'] == 'Malicious'
    finally:
        # Clean system from created module
        int_delete_module_instance(
            entity_id=module_instance['id'], **{'headers': module_headers})
