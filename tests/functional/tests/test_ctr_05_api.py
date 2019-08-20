import pytest

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


def test_ctr_positive_smoke_inspect(module_headers):
    """Perform testing for inspect end point of threat response application
    server

    ID: aaf14b29-9f5a-41aa-805e-73398ed2b112

    Steps:

        1. Send request with domain name to inspect end point

    Expectedresults: POST action reached end point and returned correct data

    Importance: High
    """
    request_content = 'cisco.com'
    response = inspect(
        payload={'content': request_content},
        **{'headers': module_headers}
    )
    assert response[0]['value'] == request_content
    assert response[0]['type'] == 'domain'


def test_ctr_positive_tool_inspect(module_headers, module_tool_client):
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


def test_ctr_positive_tool_enrich_observe_observables(
        module_headers, module_tool_client):
    """Perform testing for enrich observe observables end point of custom
        threat response python module

    ID: d1dd6d3b-f762-4280-a573-7cc815da5a85

    Steps:

        1. Send request sha256 hash to enrich observe observables end point of
            threat response server using direct POST call
        2. Send same request using custom python module
        3. Compare results

    Expectedresults: POST action finished get to the end point and return
        correct data

    Importance: Critical
    """
    data = '01f30887a828344f6cf574bb05bd0bf571fc35979a3032377b95fb0d692b8061'
    response = enrich_observe_observables(
        payload=[{'type': 'sha256', 'value': data}],
        **{'headers': module_headers}
    )['data']
    tool_response = module_tool_client.enrich.observe.observables(
        [{'type': 'sha256', 'value': data}])['data']
    direct_observables = get_observables(response, 'VirusTotal')
    tool_observables = get_observables(tool_response, 'VirusTotal')
    assert tool_observables['data']['verdicts']['count'] > 0, (
        'No observables returned from server. Check hash value')
    assert tool_observables['data']['judgements']['count'] > 0, (
        'No observables returned from server. Check hash value')
    assert tool_observables[
        'data']['verdicts']['docs'][0]['disposition_name'] == 'Malicious'
    assert direct_observables['data']['judgements'][
        'count'] == tool_observables['data']['judgements']['count']


def test_ctr_positive_tool_enrich_deliberate_observables(
        module_headers, module_tool_client):
    """Perform testing for enrich deliberate observables end point of custom
        threat response python module

    ID: 2deb7d0f-a44f-49d6-81f1-5a6e16e7d652

    Steps:

        1. Send request sha256 hash to enrich deliberate observables end
            point of threat response server using direct POST call
        2. Send same request using custom python module
        3. Compare results

    Expectedresults: POST action finished get to the end point and return
        correct data

    Importance: Critical
    """
    data = '01f30887a828344f6cf574bb05bd0bf571fc35979a3032377b95fb0d692b8061'
    response = enrich_deliberate_observables(
        payload=[{'type': 'sha256', 'value': data}],
        **{'headers': module_headers}
    )['data']
    tool_response = module_tool_client.enrich.deliberate.observables(
        [{'type': 'sha256', 'value': data}])['data']
    direct_observables = get_observables(response, 'VirusTotal')
    tool_observables = get_observables(tool_response, 'VirusTotal')
    assert tool_observables['data']['verdicts']['count'] > 0, (
        'No observables returned from server. Check hash value')
    assert 'judgements' not in tool_observables['data'].keys()
    assert tool_observables[
        'data']['verdicts']['docs'][0]['type'] == 'verdict'
    assert direct_observables['data']['verdicts'][
        'count'] == tool_observables['data']['verdicts']['count']


def test_ctr_positive_tool_enrich_refer_observables(
        module_headers, module_tool_client):
    """Perform testing for enrich refer observables end point of custom
        threat response python module

    ID: 7b8d86b5-a360-4f91-acd7-f2d9e4104b03

    Steps:

        1. Send request sha256 hash to enrich refer observables end point of
            threat response server using direct POST call
        2. Send same request using custom python module
        3. Compare results

    Expectedresults: POST action finished get to the end point and return
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
