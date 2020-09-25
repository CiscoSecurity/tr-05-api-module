import time
import pytest
from requests import ReadTimeout, HTTPError

from ctrlibrary.core.datafactory import gen_sha256, gen_string
from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.inspect import inspect
from ctrlibrary.threatresponse.enrich import (
    enrich_deliberate_observables,
    enrich_observe_observables,
    enrich_refer_observables
)
from ctrlibrary.threatresponse.response import response_respond_observables
# from tests.functional.tests.utils import gen_random_token
from threatresponse import ThreatResponse
from threatresponse.exceptions import CredentialsError

IP = '95.95.0.1'
SHA256_HASH = (
    '10745318f9dd601ab76f029cbc41c7e13c9754f87eb2c85948734b2b0b148140')
DOMAIN = 'anotheratqcdata.com'


def test_ctr_positive_smoke_inspect(module_headers):
    """Perform testing for inspect end point of threat response application
    server

    ID: aaf14b29-9f5a-41aa-805e-73398ed2b112

    Steps:

        1. Send request with domain name to inspect end point

    Expectedresults: POST action successfully get to the end point and return
        correct data

    Importance: High
    """
    response = inspect(
        payload={'content': DOMAIN},
        **{'headers': module_headers}
    )
    assert response[0]['value'] == DOMAIN
    assert response[0]['type'] == 'domain'


def test_ctr_positive_timeout_support(module_headers):
    """Perform testing for inspect end point of threat response application
    server

    ID: CCTRI-eeb97060-f393-46d3-b281-602f7624e91e

    Steps:

        1. Send request with domain name and timeout to inspect end point

    Expectedresults: It is possible to use timeout as part of POST request to
        have delay and return correct data

    Importance: High
    """
    response = inspect(
        payload={'content': DOMAIN},
        **{
            'headers': module_headers,
            'timeout': 5
        }
    )
    assert response[0]['value'] == DOMAIN
    assert response[0]['type'] == 'domain'


def test_python_module_negative_endpoint_timeout(module_tool_client):
    """Perform testing of timeout argument for any threat response endpoint

    ID: CCTRI-374-8b4de3f0-2e24-444a-8631-3ddb0745be46

    Steps:

        1. Send request to inspect end point of threat response server using
            long enough timeout to finish successfully
        2. Send same request, but with short timeout, so it fail with exception

    Expectedresults: Timeout argument affects request result in expected way

    Importance: High
    """
    request_content = gen_sha256(gen_string())
    module_tool_client.inspect.inspect({'content': request_content}, timeout=5)
    with pytest.raises(ReadTimeout):
        module_tool_client.inspect.inspect(
            {'content': request_content}, timeout=0.01)


def test_python_module_positive_inspect(module_headers, module_tool_client):
    """Perform testing for inspect end point of custom threat response python
    module

    ID: 3ce73f46-7db9-4ae7-a69d-fd791c943d28

    Steps:

        1. Send request sha256 hash to inspect end point of threat response
            server using direct POST call
        2. Send same request using custom python module
        3. Compare results

    Expectedresults: Inspect requests which are sent directly and sent using
        custom tool return same responses

    Importance: Critical
    """
    direct_response = inspect(
        payload={'content': SHA256_HASH},
        **{'headers': module_headers}
    )
    tool_response = module_tool_client.inspect.inspect(
        {'content': SHA256_HASH})
    assert direct_response[0]['value'] == tool_response[0]['value']
    assert direct_response[0]['type'] == tool_response[0]['type']
    assert tool_response[0]['value'] == SHA256_HASH
    assert tool_response[0]['type'] == 'sha256'


def test_python_module_positive_enrich_observe_observables(
        module_headers, module_tool_client):
    """Perform testing for enrich observe observables end point of custom
    threat response python module

    ID: d1dd6d3b-f762-4280-a573-7cc815da5a85

    Steps:

        1. Send request sha256 hash to enrich observe observables end point of
            threat response server using direct POST call
        2. Send same request using custom python module
        3. Compare results

    Expectedresults: POST action successfully get to the end point and return
        correct data

    Importance: Critical
    """
    response = enrich_observe_observables(
        payload=[{'type': 'sha256', 'value': SHA256_HASH}],
        **{'headers': module_headers}
    )['data']
    tool_response = module_tool_client.enrich.observe.observables(
        [{'type': 'sha256', 'value': SHA256_HASH}])['data']
    direct_observables = get_observables(response, 'Private Intelligence')
    tool_observables = get_observables(tool_response, 'Private Intelligence')
    assert tool_observables['data']['verdicts']['count'] > 0, (
        'No observable verdicts returned from server. Check hash value')
    assert tool_observables['data']['judgements']['count'] > 0, (
        'No observable judgements returned from server. Check hash value')
    assert tool_observables[
        'data']['verdicts']['docs'][0]['disposition_name'] == 'Malicious'
    assert direct_observables['data']['judgements'][
        'count'] == tool_observables['data']['judgements']['count']


def test_python_module_positive_enrich_deliberate_observables(
        module_headers, module_tool_client):
    """Perform testing for enrich deliberate observables end point of custom
    threat response python module

    ID: 2deb7d0f-a44f-49d6-81f1-5a6e16e7d652

    Steps:

        1. Send request sha256 hash to enrich deliberate observables end
            point of threat response server using direct POST call
        2. Send same request using custom python module
        3. Compare results

    Expectedresults: POST action successfully get to the end point and return
        correct data

    Importance: Critical
    """
    response = enrich_deliberate_observables(
        payload=[{'type': 'sha256', 'value': SHA256_HASH}],
        **{'headers': module_headers}
    )['data']
    tool_response = module_tool_client.enrich.deliberate.observables(
        [{'type': 'sha256', 'value': SHA256_HASH}])['data']
    direct_observables = get_observables(response, 'Private Intelligence')
    tool_observables = get_observables(tool_response, 'Private Intelligence')
    assert tool_observables['data']['verdicts']['count'] > 0, (
        'No observables returned from server. Check hash value')
    assert 'judgements' not in tool_observables['data'].keys()
    assert tool_observables[
        'data']['verdicts']['docs'][0]['type'] == 'verdict'
    assert direct_observables['data']['verdicts'][
        'count'] == tool_observables['data']['verdicts']['count']


def test_python_module_positive_enrich_refer_observables(
        module_headers, module_tool_client):
    """Perform testing for enrich refer observables end point of custom
    threat response python module

    ID: 7b8d86b5-a360-4f91-acd7-f2d9e4104b03

    Steps:

        1. Send request sha256 hash to enrich refer observables end point of
            threat response server using direct POST call
        2. Send same request using custom python module
        3. Compare results

    Expectedresults: POST action successfully get to the end point and return
        correct data

    Importance: Critical
    """
    response = enrich_refer_observables(
        payload=[{'type': 'domain', 'value': DOMAIN}],
        **{'headers': module_headers}
    )['data'][0]
    tool_response = module_tool_client.enrich.refer.observables(
        [{'type': 'domain', 'value': DOMAIN}])['data'][0]
    assert tool_response['module']
    assert tool_response['title'] == 'Search for this domain'
    assert response == tool_response


def test_python_module_positive_response_respond_observables_by_hash(
        module_headers, module_tool_client):
    """Perform testing for response respond observables end point of custom
    threat response python module by hash type

    ID: CCTRI-137-b8f74c6e-b670-4159-8d74-eb4756b24084

    Steps:

        1. Send request sha256 hash to response respond observables end
            point of threat response server using direct POST call
        2. Send same request using custom python module
        3. Compare results

    Expectedresults: POST action successfully get to the end point and return
        correct data

    Importance: Critical
    """
    expected_list = [
        'Add SHA256 to custom detections 500 PDFs',
        'Add SHA256 to custom detections File Blacklist',
        'Add SHA256 to custom detections testing'
    ]
    response = response_respond_observables(
        payload=[{'type': 'sha256', 'value': SHA256_HASH}],
        **{'headers': module_headers}
    )['data']
    tool_response = module_tool_client.response.respond.observables(
        [{'type': 'sha256', 'value': SHA256_HASH}])['data']
    assert len(tool_response) > 0
    assert set(expected_list) == set([d['title'] for d in tool_response])
    assert response == tool_response


def test_python_module_positive_response_respond_observables_by_domain(
        module_headers, module_tool_client):
    """Perform testing for response respond observables end point of custom
    threat response python module by domain type

    ID: CCTRI-137-38e4089c-7ca5-4c0a-820d-e6124e939428

    Steps:

        1. Send domain name in request to response respond observables end
            point of threat response server using direct POST call
        2. Send same request using custom python module
        3. Compare results

    Expectedresults: POST action successfully get to the end point and return
        correct data

    Importance: Critical
    """
    response = response_respond_observables(
        payload=[{'type': 'domain', 'value': DOMAIN}],
        **{'headers': module_headers}
    )['data']
    tool_response = module_tool_client.response.respond.observables(
        [{'type': 'domain', 'value': DOMAIN}])['data']
    assert len(tool_response) > 0
    assert tool_response[0]['module'] == 'Umbrella'
    assert tool_response[0]['title'] == 'Block this domain'
    assert response == tool_response


def test_python_module_positive_commands_verdict(module_tool_client):
    """Perform testing for verdict command from custom threat response python
    module for one observable

    ID: CCTRI-385-9f8cc790-a316-4e82-b592-43229f85e381

    Steps:

        1. Get observable verdict using default deliberate observable request
        2. Get observable verdict using our new tool command

    Expectedresults: Verdict command for provided observable returns expected
        values and disposition name is the same in comparison to direct server
        request

    Importance: Critical
    """
    tool_response = module_tool_client.enrich.deliberate.observables(
        [{'type': 'sha256', 'value': SHA256_HASH}])['data']
    tool_observables = get_observables(tool_response, 'Private Intelligence')
    assert tool_observables['data']['verdicts']['count'] > 0, (
        'No observable verdicts returned from server. Check hash value')
    assert tool_observables[
        'data']['verdicts']['docs'][0]['disposition_name'] == 'Malicious'

    tool_command_response = module_tool_client.commands.verdict(SHA256_HASH)
    tool_command_observable = get_observables(
        tool_command_response['verdicts'], 'Private Intelligence')
    assert tool_command_observable['observable_value'] == SHA256_HASH
    assert tool_command_observable['observable_type'] == 'sha256'
    assert tool_command_observable['expiration'] is not None
    assert tool_command_observable['module'] == 'Private Intelligence'
    assert tool_command_observable['module_type_id']
    assert tool_command_observable['module_instance_id']
    assert tool_command_observable['disposition_name'] == 'Malicious'


def test_python_module_positive_commands_verdict_multiple(module_tool_client):
    """Perform testing for verdict command from custom threat response python
    module for multiple observable

    ID: CCTRI-385-9d42b99e-13ac-4f4e-b142-5e6781db4b00

    Steps:

        1. Get verdict using our new tool command for both hash and ip
            observables

    Expectedresults: Verdict command for provided observables returns expected
        values

    Importance: Critical
    """
    tool_command_response = module_tool_client.commands.verdict((
        SHA256_HASH, IP))
    tool_command_hash_observable = [
        d
        for d in tool_command_response['verdicts']
        if d['observable_value'] == SHA256_HASH and (
            d['module'] == 'Private Intelligence')
    ][0]
    tool_command_ip_observable = [
        d
        for d in tool_command_response['verdicts']
        if d['observable_value'] == IP and (
            d['module'] == 'Private Intelligence')
    ][0]
    assert tool_command_hash_observable['observable_type'] == 'sha256'
    assert tool_command_hash_observable['disposition_name'] == 'Malicious'
    assert tool_command_ip_observable['observable_value'] == IP
    assert tool_command_ip_observable['observable_type'] == 'ip'
    assert tool_command_ip_observable['module_type_id']
    assert tool_command_ip_observable['module_instance_id']
    assert tool_command_ip_observable['disposition_name'] == 'Malicious'


def test_python_module_positive_commands_target(module_tool_client):
    """Perform testing for target command from custom threat response python
    module for the observable

    ID: CCTRI-422-c701fb34-8d35-4407-b103-0f319171e30d

    Steps:

        1. Get observable targets using our new tool command

    Expectedresults: Target command for provided observable returns expected
        values

    Importance: Critical
    """
    expected_target = [
        {'value': 'new_demo_endpoint', 'type': 'hostname'},
        {'value': '44:cc:7a:aa:1d:bb', 'type': 'mac_address'},
        {'value': '192.168.4.4', 'type': 'ip'}
    ]
    tool_command_response = module_tool_client.commands.targets(
        SHA256_HASH)['targets']
    tool_command_targets = get_observables(
        tool_command_response, 'Private Intelligence')

    assert tool_command_targets['module'] == 'Private Intelligence'
    assert tool_command_targets['module_type_id']
    assert tool_command_targets['module_instance_id']
    # We expect 1 target for observable
    assert len(tool_command_targets['targets']) == 1
    assert tool_command_targets['targets'][0]['type'] == 'endpoint'
    assert tool_command_targets['targets'][0]['observables'] == expected_target


def test_python_module_positive_token(module_tool_client_token):
    """Perform testing of availability perform request to the Threat response
    using token

    ID: CCTRI-1579-8f1c20ea-fe40-11ea-adc1-0242ac120002

    Steps:

        1. Inspect observable using token
        2. Sleep and wait until token will expired

    Expectedresults: Inspect for provided observable returns expected
        values, wait until token will expired and check that exception
        raises

    Importance: Critical
    """
    assert module_tool_client_token.inspect.inspect(
        {'content': '1.1.1.1'}) == [
               {'type': 'ip', 'value': '1.1.1.1'}
           ]
    time.sleep(601)
    try:
        assert not module_tool_client_token.inspect.inspect(
            {'content': '1.1.1.1'}) == [
                       {'type': 'ip', 'value': '1.1.1.1'}
        ]
    except HTTPError:
        pass


@pytest.mark.parametrize(
    'token',
    ('',
     'dsadasd')
)
def test_python_module_negative_token(module_tool_client_token, token):
    """Perform testing of availability perform request to the Threat response
    using invalid token

    ID: CCTRI-1579-4ca2a94f-db81-44c9-bf5b-53146cfd127a

    Steps:

        1. Inspect observable using empty token
        2. Inspect observable using invalid token

    Expectedresults: Inspect for provided observable doesn't returns expected
        values, because token is invalid

    Importance: Critical
    """
    try:
        assert not (ThreatResponse(
            token=token).inspect.inspect({'content': '1.1.1.1'})) == [
            {'type': 'ip', 'value': '1.1.1.1'}]
    except (HTTPError, CredentialsError):
        pass
