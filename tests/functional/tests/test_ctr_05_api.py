import pytest

from requests import ReadTimeout

from ctrlibrary.core import settings
from ctrlibrary.threatresponse import token
from ctrlibrary.core.datafactory import gen_sha256, gen_string
from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.inspect import inspect
from ctrlibrary.threatresponse.enrich import (
    enrich_deliberate_observables,
    enrich_observe_observables,
    enrich_refer_observables
)
from ctrlibrary.threatresponse.response import response_respond_observables
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

# TODO Add some test coverage for VirusTotal module once we can get stable
# TODO response from CTR server


SHA256_HASH = (
    '6a37d750f02de99767770a2d1274c3a4e0259e98d38bd8a801949ae3972eef86')

DOMAIN = 'cpi-istanbul.com'


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
    request_content = 'cisco.com'
    response = inspect(
        payload={'content': request_content},
        **{'headers': module_headers}
    )
    assert response[0]['value'] == request_content
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
    request_content = 'cisco.com'
    response = inspect(
        payload={'content': request_content},
        **{
                'headers': module_headers,
                'timeout': 5
           }
    )
    assert response[0]['value'] == request_content
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
    request_content = gen_sha256(gen_string())
    direct_response = inspect(
        payload={'content': request_content},
        **{'headers': module_headers}
    )
    tool_response = module_tool_client.inspect.inspect(
        {'content': request_content})
    assert direct_response[0]['value'] == tool_response[0]['value']
    assert direct_response[0]['type'] == tool_response[0]['type']
    assert tool_response[0]['value'] == request_content
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
    direct_observables = get_observables(response, 'AMP File Reputation')
    tool_observables = get_observables(tool_response, 'AMP File Reputation')
    assert tool_observables['data']['verdicts']['count'] > 0, (
        'No observables returned from server. Check hash value')
    assert tool_observables['data']['judgements']['count'] > 0, (
        'No observables returned from server. Check hash value')
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
    direct_observables = get_observables(response, 'AMP File Reputation')
    tool_observables = get_observables(tool_response, 'AMP File Reputation')
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
    request_content = 'cisco.com'
    response = enrich_refer_observables(
        payload=[{'type': 'domain', 'value': request_content}],
        **{'headers': module_headers}
    )['data'][0]
    tool_response = module_tool_client.enrich.refer.observables(
        [{'type': 'domain', 'value': request_content}])['data'][0]
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
    assert tool_response[0]['title'] == 'Unblock this domain'
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
    tool_observables = get_observables(tool_response, 'AMP File Reputation')
    assert tool_observables['data']['verdicts']['count'] > 0, (
        'No observables returned from server. Check hash value')
    assert tool_observables[
        'data']['verdicts']['docs'][0]['disposition_name'] == 'Malicious'

    tool_command_response = module_tool_client.commands.verdict(SHA256_HASH)
    tool_command_observable = get_observables(
        tool_command_response['verdicts'], 'AMP File Reputation')
    assert tool_command_observable['observable_value'] == SHA256_HASH
    assert tool_command_observable['observable_type'] == 'sha256'
    assert tool_command_observable['expiration'] is not None
    assert tool_command_observable['module'] == 'AMP File Reputation'
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
    ip = '97.74.4.114'
    tool_command_response = module_tool_client.commands.verdict((
        SHA256_HASH, ip))
    tool_command_hash_observable = get_observables(
        tool_command_response['verdicts'], 'AMP File Reputation')
    assert tool_command_hash_observable['observable_value'] == SHA256_HASH
    assert tool_command_hash_observable['disposition_name'] == 'Malicious'
    tool_command_ip_observable = get_observables(
        tool_command_response['verdicts'], 'Umbrella')
    assert tool_command_ip_observable['observable_value'] == ip
    assert tool_command_ip_observable['observable_type'] == 'ip'
    assert tool_command_ip_observable['module'] == 'Umbrella'
    assert tool_command_ip_observable['disposition_name'] == 'Unknown'


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
    HASH_WITH_TARGET = (
        '5ad3c37e6f2b9db3ee8b5aeedc474645de90c66e3d95f8620c48102f1eba4124')
    DEMO_TARGET = [
        {'value': 'Demo_AMP_Threat_Audit', 'type': 'hostname'},
        {
            'value': '2e1d4e1b-0577-4fe6-9e07-7d08375c9275',
            'type': 'amp_computer_guid'
        },
        {'value': '151.126.157.6', 'type': 'ip'},
        {'value': '5f:99:5f:43:5e:6b', 'type': 'mac_address'}
    ]
    tool_command_response = module_tool_client.commands.targets(
        HASH_WITH_TARGET)['targets']
    tool_command_targets = get_observables(
        tool_command_response, 'AMP for Endpoints')['targets']
    # We expect 2 targets for observable
    assert len(tool_command_targets) == 2
    # Get one target from the list and compare values to expected ones
    target = [
        d for d
        in tool_command_targets
        if d['observables'][0]['value'] == 'Demo_AMP_Threat_Audit'
    ][0]
    assert target['type'] == 'endpoint'
    assert target['observables'] == DEMO_TARGET
    assert target['os'] == 'Windows 10, SP 0.0'
