from threatresponse.api import CommandsAPI
from threatresponse.api.commands import build_array_for_targets, \
    build_array_for_verdicts

from .assertions import *


def test_command_verdict_succeeds():
    request = invoke(CommandsAPI, lambda api: api.verdict(payload),
                     command=True)

    assert request.perform.mock_calls[0].args == (
        'POST', '/iroh/iroh-inspect/inspect')
    assert request.perform.mock_calls[0].kwargs == (
        {'json': {'content': "{'ham': 'eggs'}"}})
    assert request.perform.mock_calls[1].args == (
        'POST', '/iroh/iroh-enrich/deliberate/observables')
    assert request.perform.mock_calls[1].kwargs == ({'json': {'ham': 'eggs'}})


def test_command_targets_succeeds():
    request = invoke(CommandsAPI, lambda api: api.targets(payload),
                     command=True)

    assert request.perform.mock_calls[0].args == (
        'POST', '/iroh/iroh-inspect/inspect')
    assert request.perform.mock_calls[0].kwargs == (
        {'json': {'content': "{'ham': 'eggs'}"}})
    assert request.perform.mock_calls[1].args == (
        'POST', '/iroh/iroh-enrich/observe/observables')
    assert request.perform.mock_calls[1].kwargs == ({'json': {'ham': 'eggs'}})


def test_build_array_for_a_verdict():
    json = {'data': [{'data':
                          {'verdicts':
                               {'count': 1,
                                'docs': [
                                    {'valid_time':
                                        {
                                            'start_time': '2020-02-06T13:19:39.499Z',
                                            'end_time': '2020-03-07T13:19:39.499Z'},
                                        'observable': {'type': 'domain',
                                                       'value': 'value'},
                                        'type': 'verdict',
                                        'disposition': 5}]}},
                      'module-type': 'module_type',
                      'module': 'first_module'},
                     {'data':
                          {'verdicts':
                               {'count': 1,
                                'docs': [
                                    {'valid_time':
                                        {
                                            'start_time': '2020-02-06T13:19:39.499Z'},
                                        'observable': {'type': 'domain',
                                                       'value': 'value'},
                                        'type': 'verdict',
                                        'disposition': 3}]}},
                      'module-type': 'module_type',
                      'module': 'second_module'},
                     {'data':
                          {'verdicts':
                               {'count': 1,
                                'docs': [
                                    {'valid_time':
                                        {
                                            'start_time': '2020-02-06T13:19:39.875Z',
                                            'end_time': '2020-03-07T13:19:39.875Z'},
                                        'observable': {'type': 'domain',
                                                       'value': 'value'},
                                        'type': 'verdict',
                                        'disposition': 1}]}},
                      'module-type': 'module_type',
                      'module': 'third_module'}]}
    array_for_a_verdict = build_array_for_verdicts(json)
    assert array_for_a_verdict == [
        {'disposition_name': 'Unknown', 'observable_value': 'value',
         'expiration': '2020-03-07T13:19:39.499Z',
         'module': 'first_module', 'observable_type': 'domain'},
        {'disposition_name': 'Suspicious', 'observable_value': 'value',
         'expiration': '',  # N/A
         'module': 'second_module', 'observable_type': 'domain'},
        {'disposition_name': 'Clean', 'observable_value': 'value',
         'expiration': '2020-03-07T13:19:39.875Z',
         'module': 'third_module', 'observable_type': 'domain'}]


def test_build_array_for_targets():
    json = {
        'data': [
            {
                'data': {
                    'sightings': {
                        'count': 1,
                        'docs': [
                            {
                                'targets': [
                                    {
                                        'observables': [
                                            {
                                                'type': 'email',
                                                'value': 'example.com'
                                            }
                                        ],
                                        'type': 'email',
                                    }
                                ],
                            }
                        ]
                    }
                },
                'module-type': 'module_type',
                'module': 'module'
            }
        ]
    }
    array_for_a_targets = build_array_for_targets(json)
    assert array_for_a_targets == [{'targets': [
        {'observables': [{'type': 'email', 'value': 'example.com'}],
         'type': 'email'}], 'module': 'module'}]
